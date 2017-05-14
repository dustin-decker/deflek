package main

import (
	"bytes"
	"encoding/json"
	"errors"
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
	ListenInterface      string
	ListenPort           int
	Target               string
	TargetPathPrefix     string
	WhitelistedRoutes    string
	AnonymousMetricsUser bool
	RBAC                 struct {
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
	path := strings.TrimPrefix(r.URL.Path, C.TargetPathPrefix)

	// Check Kibana queries against whitelisted indices
	search, _ := regexp.Compile(`^\/elasticsearch\/_msearch`)
	if search.MatchString(path) {
		whitelistedIndices, err := GetWhitelistedIndices(r, C)
		if err != nil {
			fmt.Println(err.Error())
			return false
		}

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
			return false
		}
		// add the rest of the fields
		err = decoder.Decode(&f.X)
		if err != nil {
			return false
		}
		for _, index := range f.Index {
			if !goutil.StringInSlice(index, whitelistedIndices) {
				fmt.Printf("%s not in index whitelist", index)
				return false
			}
		}
	}

	// Check against whitelisted routes
	for _, regexp := range p.routePatterns {
		fmt.Println(r.URL.Path)
		if !regexp.MatchString(path) {
			fmt.Printf("Not accepted routes %x", r.URL.Path)
			return false
		}
	}

	fmt.Println(r.URL.Fragment)

	return true
}

// GetWhitelistedIndices returns indices whitelisted for the user and group provided
func GetWhitelistedIndices(r *http.Request, C *Config) ([]string, error) {

	var whitelistedIndices []string

	// Username is trusted input provided by a SSO proxy layer
	var username string
	if _, ok := r.Header["Username"]; ok {
		username = r.Header["Username"][0]
	} else {
		if C.AnonymousMetricsUser {
			username = "metrics"
		} else {
			return whitelistedIndices, errors.New(("No Username header provided"))
		}
	}

	var groups []string
	// Group is trusted input provided by a SSO proxy layer
	if _, ok := r.Header["Groups"]; ok {
		groups = r.Header["Groups"]
	}
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
	return whitelistedIndices, nil
}

func main() {
	// Get config
	viper.SetConfigName("config") // name of config file (without extension)\
	// yaml, toml, json, ini, it don't care
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s", err))
	}

	var C Config
	err = viper.Unmarshal(&C)
	if err != nil {
		panic(fmt.Errorf("Unable to decode config into struct: %v", err))
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
	http.ListenAndServe(fmt.Sprintf("%s:%d", C.ListenInterface, C.ListenPort), nil)
}
