package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	glob "github.com/ryanuber/go-glob"
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

func (p *Prox) checkRBAC(r *http.Request, C *Config, trace *AppTrace) (bool, error) {
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

	ok, err := indexPermitted(trace, r, C)
	if err != nil || !ok {
		return false, err
	}

	canManage, err := canManage(r, C)
	if err != nil {
		return false, err
	}

	// Control Kibana index pattern access
	if !canManage && strings.HasPrefix(r.URL.Path, "/elasticsearch/.kibana/index-pattern") && !strings.HasPrefix(r.URL.Path, "/elasticsearch/.kibana/index-pattern/_search") {
		err = fmt.Errorf("Cannot manage %s", r.URL.Path)
		return false, err
	}
	// Control Kibana's Dev API console access
	if !canManage && strings.HasPrefix(r.URL.Path, "/api/console") {
		err = fmt.Errorf("Cannot manage %s", r.URL.Path)
		return false, err
	}

	return true, nil
}

func canManage(r *http.Request, C *Config) (bool, error) {
	groups, _ := getGroups(r, C)

	// Can any of the groups manage?
	for _, group := range groups {
		if configGroup, ok := C.RBAC.Groups[group]; ok {
			if configGroup.CanManage == true {
				return true, nil
			}
		}
	}

	return false, nil
}

func getUser(r *http.Request, C *Config) (string, error) {
	// Username is trusted input provided by a SSO proxy layer
	var username string
	if _, ok := r.Header[C.UserHeaderName]; ok {
		username = r.Header[C.UserHeaderName][0]
	}

	return username, nil
}

func getGroups(r *http.Request, C *Config) ([]string, error) {
	// Group is trusted input provided by a SSO proxy layer
	if _, ok := r.Header[C.GroupHeaderName]; ok {
		rawGroups := r.Header[C.GroupHeaderName][0]
		switch groupType := C.GroupHeaderType; groupType {
		case "AD":
			groups := getAdGroups(rawGroups)
			return groups, nil
		default:
			groups := []string{C.AnonymousGroup}
			return groups, nil
		}
	}
	groups := []string{C.AnonymousGroup}
	return groups, nil
}

func getAdGroups(rawGroups string) []string {
	var groups []string
	splitKV := strings.Split(rawGroups, ",")
	for _, kv := range splitKV {
		splitSemiColins := strings.Split(kv, ";")
		for _, kv2 := range splitSemiColins {
			if strings.HasPrefix(kv2, "CN=") {
				newGroup := strings.ToLower(strings.TrimLeft(kv2, "CN="))
				groups = append(groups, newGroup)
			}
		}
	}
	return groups
}

func getWhitelistedIndices(r *http.Request, C *Config) ([]Index, error) {
	var indices []Index
	groups, err := getGroups(r, C)
	if err != nil {
		return indices, err
	}

	for _, group := range groups {
		if configGroup, ok := C.RBAC.Groups[group]; ok {
			for _, configIndex := range configGroup.WhitelistedIndices {
				indices = append(indices, configIndex)
			}
		}
	}

	return indices, nil
}

type requestContext struct {
	trace              *AppTrace
	r                  *http.Request
	c                  *Config
	whitelistedIndices []Index
	index              string
}

func filterMsearch(ctx requestContext) (bool, error) {
	body, err := getBody(ctx.r)
	if err != nil {
		return false, err
	}
	ctx.trace.Query = string(body)

	// They're sending newline deliminated JSON blobs :/
	// Savages.
	firstRoot := bytes.Split(body, []byte("\n"))[0]

	f := SearchReq{}
	err = json.Unmarshal(firstRoot, &f)
	if err != nil {
		return false, err
	}
	err = json.Unmarshal(firstRoot, &f.X)
	if err != nil {
		return false, err
	}

	// Trace indices
	var indices []string
	switch jv := f.Index.(type) {
	// ES 2.X uses index string
	case string:
		indices = []string{jv}
	// ES 5 uses JSON array of indices
	case []interface{}:
		for _, v := range jv {
			indices = append(indices, v.(string))
		}
	default:
		return false, fmt.Errorf("Unknown type %v returned for json field 'index'",
			reflect.TypeOf(f.Index))
	}
	ctx.trace.Index = indices

	// Check if index is is the whitelist
	for _, index := range indices {
		permitted, err := indexBodyPermitted(index, ctx.r, ctx.c)
		if err != nil {
			return false, err
		}
		if !permitted {
			err = fmt.Errorf("%s not in index whitelist", index)
			return false, err
		}
	}
	return true, err
}

func indexPermitted(trace *AppTrace, r *http.Request, C *Config) (bool, error) {
	index := strings.Split(r.URL.Path, "/")[1]

	whitelistedIndices, err := getWhitelistedIndices(r, C)
	if err != nil {
		return false, err
	}

	ctx := requestContext{
		trace:              trace,
		r:                  r,
		c:                  C,
		whitelistedIndices: whitelistedIndices,
		index:              index,
	}

	switch true {
	case index == "_all" || index == "_search":
		// maybe this query can be re-written against permitted indices
		return false, errors.New("Searching all indices is not supported at this time")

	case index == "_msearch":
		filterMsearch(ctx)

	case index == "_mget":
		body, _ := getBody(r)
		trace.Query = string(body)
		return false, errors.New("Searching with is not supported at this time")

	}

	// Index API endpoints begin with the index name
	// Other API endpoints begin with '_'
	if !strings.HasPrefix(index, "_") && len(index) > 0 {
		trace.Index = []string{index}
		if r.Method == "POST" {
			body, err := getBody(r)
			if err != nil {
				return false, err
			}
			trace.Query = string(body)
		}

		// req'd by Visual Builder
		if r.URL.Path == "/*/_field_stats" {
			return true, nil
		}

		// TODO for Visual Builder
		// Replace * with all indices they have access to... :(
		//  {"code":403,"elasped":0,"groups":"[group2]","index":"[*]","lvl":"eror","method":"POST","msg":"* not in index whitelist","path":"/_msearch","query":"{\"index\":[\"*\"],\"ignore\":[404],\"timeout\":\"90s\",\"requestTimeout\":90000,\"ignoreUnavailable\":true}\n{\"size\":0,\"query\":{\"bool\":{\"must\":[{\"range\":{\"@timestamp\":{\"gte\":1339990677678,\"lte\":1497152277679,\"format\":\"epoch_millis\"}}},{\"bool\":{\"must\":[{\"query_string\":{\"query\":\"*\"}}],\"must_not\":[]}}]}},\"aggs\":{\"ec3c3e41-53d5-11e7-80ea-7bfec2933998\":{\"filter\":{\"match_all\":{}},\"aggs\":{\"timeseries\":{\"date_histogram\":{\"field\":\"@timestamp\",\"interval\":\"604800s\",\"min_doc_count\":0,\"extended_bounds\":{\"min\":1339990677678,\"max\":1497152277679}},\"aggs\":{\"ec3c3e42-53d5-11e7-80ea-7bfec2933998\":{\"bucket_script\":{\"buckets_path\":{\"count\":\"_count\"},\"script\":{\"inline\":\"count * 1\",\"lang\":\"expression\"},\"gap_policy\":\"skip\"}}}}}}}}\n","t":"2017-06-18T03:37:57.786407134Z","user":""}

		for _, whitelistedIndex := range whitelistedIndices {
			if glob.Glob(whitelistedIndex.Name, index) {
				for _, method := range whitelistedIndex.RESTverbs {
					if r.Method == method {
						return true, nil
					}
				}
				return false, errors.New("Method not allowed on index")
			}
		}
		return false, errors.New("Index not allowed")
	}

	return true, nil
}

func indexBodyPermitted(index string, r *http.Request, C *Config) (bool, error) {
	groups, _ := getGroups(r, C)
	for _, group := range groups {
		if configGroup, ok := C.RBAC.Groups[group]; ok {
			for _, configIndex := range configGroup.WhitelistedIndices {
				if glob.Glob(configIndex.Name, index) {
					return true, nil
				}
			}
		}
	}
	return false, nil
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
