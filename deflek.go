package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"regexp"
	"time"

	"github.com/inconshreveable/log15"
	yaml "gopkg.in/yaml.v2"
)

// SearchReq unmarshalls index field from Elasticsearch multi-search API request json body
type SearchReq struct {
	Index interface{}            `json:"index"`
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
	GroupHeaderName   string `yaml:"group_header_name"`
	GroupHeaderType   string `yaml:"group_header_type"`
	UserHeaderName    string `yaml:"user_header_name"`
	RBAC              struct {
		Groups map[string]Permissions
	}
}

// Permissions structure for groups and users
type Permissions struct {
	WhitelistedIndices []Index `yaml:"whitelisted_indices"`
	CanManage          bool    `yaml:"can_manage"`
}

// Index struct defines index and REST verbs allowed
type Index struct {
	Name      string
	RESTverbs []string `yaml:"rest_verbs"`
}

// AppTrace - Request error handling wrapper on the handler
type AppTrace struct {
	Path    string
	Method  string
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

func (p *Prox) filterRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	trace := AppTrace{}
	trans := traceTransport{}
	p.proxy.Transport = &trans

	_, err := p.checkRBAC(r, p.config, &trace)
	if err != nil {
		trace.Error = err.Error()
	} else {
		p.proxy.ServeHTTP(w, r)
	}

	trace.Elapsed = int(time.Since(start) / time.Millisecond)
	if trans.Response != nil {
		trace.Code = trans.Response.StatusCode
	} else {
		trace.Code = 403
	}

	trace.Method = r.Method

	fields := log15.Ctx{
		"code":    trace.Code,
		"method":  trace.Method,
		"path":    trace.Path,
		"elasped": trace.Elapsed,
		"user":    trace.User,
		"groups":  trace.Groups,
		"query":   trace.Query,
		"index":   trace.Index,
	}

	if err != nil {
		p.log.Error(trace.Error, fields)
	} else {
		p.log.Info(trace.Message, fields)
	}
}

func (t *traceTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	res, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		return res, err
	}

	if res.Header.Get("Content-Encoding") == "gzip" {
		body, err := gzip.NewReader(res.Body)
		if err != nil {
			return res, err
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

func getBody(r *http.Request) ([]byte, error) {
	var body []byte
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return body, err
	}
	rdr1 := ioutil.NopCloser(bytes.NewBuffer(buf))
	body, err = ioutil.ReadAll(rdr1)
	if err != nil {
		return body, err
	}
	// If we don't keep a second reader untouched, we will consume
	// the request body when reading it
	rdr2 := ioutil.NopCloser(bytes.NewBuffer(buf))
	// restore the body from the second reader
	r.Body = rdr2

	return body, nil
}

func (C *Config) getConf() *Config {

	pwd, _ := os.Getwd()
	yamlFile, err := ioutil.ReadFile(path.Join(pwd, "config.yaml"))
	if err != nil {
		log15.Error(err.Error())
		os.Exit(1)
	}
	err = yaml.Unmarshal(yamlFile, C)
	if err != nil {
		log15.Error(err.Error())
		os.Exit(1)
	}

	return C
}

func main() {
	var C Config
	C.getConf()

	proxy := NewProx(&C)

	// reg, err := regexp.Compile(C.WhitelistedRoutes)
	// if err != nil {
	// 	log15.Error("Error compiling whitelistedRoutes regex: %s", err)
	// }
	// routes := []*regexp.Regexp{reg}
	// proxy.routePatterns = routes

	http.HandleFunc("/", proxy.filterRequest)
	http.ListenAndServe(fmt.Sprintf("%s:%d", C.ListenInterface, C.ListenPort), nil)
}
