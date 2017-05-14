package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"github.com/sevoma/goutil"
	"github.com/spf13/viper"
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
}

// Config for reverse proxy settings and RBAC users and groups
// Unmarshalled from config on disk
type Config struct {
	Port              string
	Target            string
	TargetPathPrefix  string
	WhitelistedRoutes string
	RBAC              struct {
		Groups map[string]Permissions
		Users  map[string]Permissions
	}
}

// Permissions structure for groups and users
type Permissions struct {
	WhitelistedIndices []string
	CanManage          bool
}

// NewProx returns new reverse proxy instance
func NewProx(C *Config) *Prox {
	url, _ := url.Parse(C.Target)

	return &Prox{config: C, target: url, proxy: httputil.NewSingleHostReverseProxy(url)}
}

func (p *Prox) handle(w http.ResponseWriter, r *http.Request) {

	if p.checkWhiteLists(r, p.config) {
		p.proxy.ServeHTTP(w, r)
	}
}

func (p *Prox) checkWhiteLists(r *http.Request, C *Config) bool {

	// Username is trusted input provided by a SSO proxy layer
	var username string
	if _, ok := r.Header["Username"]; ok {
		username = r.Header["Username"][0]
	} else {
		return false
	}

	var groups []string
	// Group is trusted input provided by a SSO proxy layer
	if _, ok := r.Header["Groups"]; ok {
		groups = r.Header["Groups"]
	}
	var whitelistedIndices []string
	for _, group := range groups {
		if _, ok := C.RBAC.Groups[group]; ok {
			whitelistedIndices = append(whitelistedIndices,
				C.RBAC.Groups[group].WhitelistedIndices...)
		}
	}
	if _, ok := C.RBAC.Users[username]; ok {
		for _, group := range C.RBAC.Users[username].WhitelistedIndices {
			if !goutil.StringInSlice(group, whitelistedIndices) {
				whitelistedIndices = append(whitelistedIndices, group)
			}
		}
	}
	fmt.Printf("User %s permitted to %s indices", username, whitelistedIndices)

	// Check Kibana queries against whitelisted indices
	search, _ := regexp.Compile(`^\/elasticsearch\/_msearch`)
	if search.MatchString(r.URL.Path) {
		buf, _ := ioutil.ReadAll(r.Body)
		rdr1 := ioutil.NopCloser(bytes.NewBuffer(buf))
		// If we don't keep a second reader untouched, we will consume
		// the request body when reading it
		rdr2 := ioutil.NopCloser(bytes.NewBuffer(buf))
		r.Body = rdr2
		decoder := json.NewDecoder(rdr1)
		f := SearchReq{}
		err := decoder.Decode(&f)
		if err != nil {
			return false
		}
		// add the rest of the fields
		err = decoder.Decode(&f.X)
		if err != nil {
			return false
		}
		for _, val := range f.Index {
			if !goutil.StringInSlice(val, whitelistedIndices) {
				fmt.Printf("%s not in index whitelist", val)
				return false
			}
		}
	}

	// Check against whitelisted routes
	for _, regexp := range p.routePatterns {
		fmt.Println(r.URL.Path)
		path := strings.TrimPrefix(r.URL.Path, viper.GetString("TargetPathPrefix"))
		if !regexp.MatchString(path) {
			fmt.Printf("Not accepted routes %x", r.URL.Path)
			return false
		}
	}
	return true
}

func main() {
	// Get config
	viper.SetConfigName("config") // name of config file (without extension)
	viper.AddConfigPath(".")
	err := viper.ReadInConfig() // yaml, toml, json, ini, whatever
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s", err))
	}

	var C Config
	err = viper.Unmarshal(&C)
	if err != nil {
		panic(fmt.Errorf("unable to decode into struct, %v", err))
	}

	whitelistedRoutes := viper.GetString("WhitelistedRoutes")

	reg, err := regexp.Compile(whitelistedRoutes)
	if err != nil {
		panic(fmt.Errorf("Error compiling whitelistedRoutes regex: %s", err))
	}
	routes := []*regexp.Regexp{reg}

	proxy := NewProx(&C)
	proxy.routePatterns = routes

	http.HandleFunc("/", proxy.handle)
	http.ListenAndServe(fmt.Sprintf(":%s", C.Port), nil)
}
