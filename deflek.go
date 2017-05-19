package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	"gopkg.in/yaml.v2"
)

// SearchReq unmarshalls index field from Kibana json request
type SearchReq struct {
	Index []string               `json:"index"`
	X     map[string]interface{} `json:"-"` // Rest of the fields should go here.
}

// Prox defines our reverse proxy
type Prox struct {
	config        *Config
	target        *url.URL
	proxy         *httputil.ReverseProxy
	routePatterns []*regexp.Regexp
	log           log15.Logger
}

// Config for reverse proxy settings and RBAC users and groups
// Unmarshalled from config on disk
type Config struct {
	ListenInterface   string `yaml:"listen_interface"`
	ListenPort        int    `yaml:"listen_port"`
	Target            string
	TargetPathPrefix  string `yaml:"target_path_prefix"`
	WhitelistedRoutes string `yaml:"whitelisted_routes"`
	AnonymousGroup    string `yaml:"anonymous_group"`
	RBAC              struct {
		Groups map[string]Permissions
		Users  map[string]Permissions
	}
}

// Permissions structure for groups and users
type Permissions struct {
	WhitelistedIndices map[string]Index `yaml:"whitelisted_indices"`
	CanManage          bool             `yaml:"can_manage"`
}

// Index struct defines index and REST verbs allowed
type Index struct {
	RESTverbs []string
}

// AppTrace - Request error handling wrapper on the handler
type AppTrace struct {
	Path    string
	Error   string
	Message string
	Code    int
	Elapsed int
	User    string
	Groups  []string
	Query   string
	Index   []string
}

// NewProx returns new reverse proxy instance
func NewProx(C *Config) *Prox {
	url, _ := url.Parse(C.Target)

	logger := log15.New()
	logger.SetHandler(log15.MultiHandler(log15.StreamHandler(os.Stderr,
		log15.JsonFormat())))

	return &Prox{
		config: C,
		target: url,
		proxy:  httputil.NewSingleHostReverseProxy(url),
		log:    logger,
	}
}

type traceTransport struct {
	Response *http.Response
}

func (p *Prox) handle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	trace := AppTrace{}
	trans := traceTransport{}
	p.proxy.Transport = &trans

	_, err := p.checkRBAC(r, p.config, &trace)
	if err != nil {
		trace.Message = err.Error()
	} else {
		p.proxy.ServeHTTP(w, r)
	}

	trace.Elapsed = int(time.Since(start) / time.Millisecond)
	if trans.Response != nil {
		trace.Code = trans.Response.StatusCode
	} else {
		trace.Code = 403
	}

	fields := log15.Ctx{
		"code":    trace.Code,
		"path":    trace.Path,
		"elasped": trace.Elapsed,
		"user":    trace.User,
		"groups":  trace.Groups,
		"query":   trace.Query,
		"index":   trace.Index,
	}

	if err != nil {
		p.log.Error(trace.Message, fields)
	} else {
		p.log.Info(trace.Message, fields)
	}
}

func (t *traceTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	res, _ := http.DefaultTransport.RoundTrip(request)

	if res.Header.Get("Content-Encoding") == "gzip" {
		body, err := gzip.NewReader(res.Body)
		if err != nil {
			fmt.Println("error")
		}
		res.Body = body
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		res.Uncompressed = true
	}

	t.Response = res

	return res, nil
}

func (p *Prox) checkRBAC(r *http.Request, C *Config, trace *AppTrace) (bool, error) {
	path := strings.TrimPrefix(r.URL.Path, C.TargetPathPrefix)
	trace.Path = path
	user, err := getUser(r, C)
	if err != nil {
		return false, err
	}
	groups, err := getGroups(r, C)
	if err != nil {
		return false, err
	}
	trace.User = user
	trace.Groups = groups

	// Check against whitelisted routes
	for _, regexp := range p.routePatterns {
		if !regexp.MatchString(path) {
			err = fmt.Errorf("Not accepted routes %x", r.URL.Path)
			return false, err
		}
	}

	// Control index pattern access
	canManage, err := canManage(r, C)
	if err != nil {
		return false, err
	}

	if !canManage && strings.HasPrefix(path, "/elasticsearch/.kibana/index-pattern") && !strings.HasPrefix(path, "/elasticsearch/.kibana/index-pattern/_search") {
		err = fmt.Errorf("Cannot manage %s", r.URL.Path)
		return false, err
	}
	// Control api console access
	if !canManage && strings.HasPrefix(path, "/api/console") {
		err = fmt.Errorf("Cannot manage %s", r.URL.Path)
		return false, err
	}

	// Check Kibana queries against whitelisted indices
	if strings.HasPrefix(path, "/elasticsearch/_msearch") {

		buf, _ := ioutil.ReadAll(r.Body)
		rdr1 := ioutil.NopCloser(bytes.NewBuffer(buf))
		// If we don't keep a second reader untouched, we will consume
		// the request body when reading it
		rdr2 := ioutil.NopCloser(bytes.NewBuffer(buf))
		r.Body = rdr2
		decoder := json.NewDecoder(rdr1)
		f := SearchReq{}
		err = decoder.Decode(&f)
		if err != nil {
			return false, err
		}
		// add the rest of the fields
		err = decoder.Decode(&f.X)
		if err != nil {
			return false, err
		}

		// Trace queries
		if q, ok := f.X["query"]; ok {
			query, err := json.Marshal(q)
			if err != nil {
				return false, err
			}
			trace.Query = string(query)
		}

		// Trace indices
		trace.Index = f.Index

		// Check if index is is the whitelist
		for _, index := range f.Index {
			permitted, err := indexPermitted(index, r, C)
			if err != nil {
				return false, err
			}
			if !permitted {
				err = fmt.Errorf("%s not in index whitelist", trimIndex(index))
				return false, err
			}
		}
	}

	return true, nil
}

func canManage(r *http.Request, C *Config) (bool, error) {
	username, err := getUser(r, C)
	if err != nil {
		return false, err
	}
	groups, _ := getGroups(r, C)

	// Can any of the groups manage?
	for _, group := range groups {
		if configGroup, ok := C.RBAC.Groups[group]; ok {
			if configGroup.CanManage == true {
				return true, nil
			}
		}
	}

	// Can the user manage?
	if configUser, ok := C.RBAC.Users[username]; ok {
		if configUser.CanManage == true {
			return true, nil
		}
	}

	return false, nil
}

func getUser(r *http.Request, C *Config) (string, error) {
	// Username is trusted input provided by a SSO proxy layer
	var username string
	if _, ok := r.Header["Username"]; ok {
		username = r.Header["Username"][0]
	}

	return username, nil
}

func getGroups(r *http.Request, C *Config) ([]string, error) {
	// Group is trusted input provided by a SSO proxy layer
	var groups []string
	if _, ok := r.Header["Groups"]; ok {
		groups = r.Header["Groups"]
	} else {
		groups = []string{C.AnonymousGroup}
	}

	return groups, nil
}

func trimIndex(index string) string {
	suffix := regexp.MustCompile(`([.a-zA-z0-9]*)-[0-9]{4}\.[0-9]{2}\.[0-9]{2}`)
	index = suffix.ReplaceAllString(index, "${1}")
	return index
}

func indexPermitted(index string, r *http.Request, C *Config) (bool, error) {
	index = trimIndex(index)

	username, err := getUser(r, C)
	if err != nil {
		return false, err
	}
	groups, _ := getGroups(r, C)

	for _, group := range groups {
		if configGroup, ok := C.RBAC.Groups[group]; ok {
			if _, ok := configGroup.WhitelistedIndices[index]; ok {
				return true, nil
			}
		}
	}

	if configUser, ok := C.RBAC.Users[username]; ok {
		if _, ok := configUser.WhitelistedIndices[index]; ok {
			return true, nil
		}
	}

	return false, nil
}

func (C *Config) getConf() *Config {

	pwd, _ := os.Getwd()
	yamlFile, err := ioutil.ReadFile(path.Join(pwd, "config.yaml"))
	if err != nil {
		log15.Error("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, C)
	if err != nil {
		log15.Error("Unmarshal: %v", err)
	}

	return C
}

func main() {
	var C Config
	C.getConf()

	reg, err := regexp.Compile(C.WhitelistedRoutes)
	if err != nil {
		log15.Error("Error compiling whitelistedRoutes regex: %s", err)
	}
	routes := []*regexp.Regexp{reg}

	proxy := NewProx(&C)
	proxy.routePatterns = routes

	http.HandleFunc("/", proxy.handle)
	http.ListenAndServe(fmt.Sprintf("%s:%d", C.ListenInterface, C.ListenPort), nil)
}
