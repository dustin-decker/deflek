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

type SearchReq struct {
	Index []string               `json:"index"`
	X     map[string]interface{} `json:"-"` // Rest of the fields should go here.
}

type Prox struct {
	target        *url.URL
	proxy         *httputil.ReverseProxy
	routePatterns []*regexp.Regexp
}

func New(target string) *Prox {
	url, _ := url.Parse(target)

	return &Prox{target: url, proxy: httputil.NewSingleHostReverseProxy(url)}
}

func (p *Prox) handle(w http.ResponseWriter, r *http.Request) {

	if p.checkWhiteLists(r) {
		p.proxy.ServeHTTP(w, r)
	}
}

func (p *Prox) checkWhiteLists(r *http.Request) bool {

	// Check Kibana queries against whitelisted indices
	search, _ := regexp.Compile(`^\/elasticsearch\/_msearch`)
	whitelistedIndicies := viper.GetStringSlice("whitelistedIndices")
	if search.MatchString(r.URL.Path) {
		buf, _ := ioutil.ReadAll(r.Body)
		rdr1 := ioutil.NopCloser(bytes.NewBuffer(buf))
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
			if !goutil.StringInSlice(val, whitelistedIndicies) {
				fmt.Printf("%s not in index whitelist", val)
				return false
			}
		}
	}

	// Check against whitelisted routes
	for _, regexp := range p.routePatterns {
		fmt.Println(r.URL.Path)
		path := strings.TrimPrefix(r.URL.Path, viper.GetString("targetPathPrefix"))
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

	port := viper.GetString("port")
	target := viper.GetString("target")
	whitelistedRoutes := viper.GetString("whitelistedRoutes")

	reg, err := regexp.Compile(whitelistedRoutes)
	if err != nil {
		panic(fmt.Errorf("Error compiling whitelistedRoutes regex: %s", err))
	}
	routes := []*regexp.Regexp{reg}

	proxy := New(target)
	proxy.routePatterns = routes

	http.HandleFunc("/", proxy.handle)
	http.ListenAndServe(":"+port, nil)
}
