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
	permissions, err := GetPermissions(r, C)

	// Check against whitelisted routes
	for _, regexp := range p.routePatterns {
		fmt.Println(r.URL.Path)
		if !regexp.MatchString(path) {
			fmt.Printf("Not accepted routes %x", r.URL.Path)
			return false
		}
	}

	// Control index pattern access
	if !permissions.CanManage && strings.HasPrefix(path, "/elasticsearch/.kibana/index-pattern") && !strings.HasPrefix(path, "/elasticsearch/.kibana/index-pattern/_search") {
		fmt.Printf("Cannot manage %s", r.URL.Path)
		return false
	}
	// Control api console access
	if !permissions.CanManage && strings.HasPrefix(path, "/api/console") {
		fmt.Printf("Cannot manage %s", r.URL.Path)
		return false
	}

	// Check Kibana queries against whitelisted indices
	if strings.HasPrefix(path, "/elasticsearch/_msearch") {

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
			suffix := regexp.MustCompile(`([a-zA-z0-9]*)-[0-9]{4}\.[0-9]{2}\.[0-9]{2}`)
			trimmedIndex := suffix.ReplaceAllString(index, "${1}")
			if !goutil.StringInSlice(trimmedIndex, permissions.WhitelistedIndices) {
				fmt.Printf("%s not in index whitelist", index)
				return false
			}
		}
	}

	return true
}

// GetPermissions returns indices whitelisted for the user and group provided
func GetPermissions(r *http.Request, C *Config) (Permissions, error) {

	var whitelistedIndices []string

	// Username is trusted input provided by a SSO proxy layer
	var username string
	var userCanManage bool
	if _, ok := r.Header["Username"]; ok {
		username = r.Header["Username"][0]
	} else {
		if C.AnonymousMetricsUser {
			username = "metrics"
		} else {
			return Permissions{}, errors.New(("No Username header provided"))
		}
	}

	// Group is trusted input provided by a SSO proxy layer
	var groups []string
	if _, ok := r.Header["Groups"]; ok {
		groups = r.Header["Groups"]
	}

	groupCanManage := false
	for _, group := range groups {
		if _, ok := C.RBAC.Groups[group]; ok {
			if C.RBAC.Groups[group].CanManage == true {
				groupCanManage = true
			}
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

	userCanManage = C.RBAC.Users[username].CanManage

	permissions := Permissions{WhitelistedIndices: whitelistedIndices,
		CanManage: (userCanManage || groupCanManage)}

	return permissions, nil
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

	reg, err := regexp.Compile(C.WhitelistedRoutes)
	if err != nil {
		panic(fmt.Errorf("Error compiling whitelistedRoutes regex: %s", err))
	}
	routes := []*regexp.Regexp{reg}

	proxy := NewProx(&C)
	proxy.routePatterns = routes

	http.HandleFunc("/", proxy.handle)
	http.ListenAndServe(fmt.Sprintf("%s:%d", C.ListenInterface, C.ListenPort), nil)
}
