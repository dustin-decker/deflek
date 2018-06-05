package main

import (
	"net/http"
	"strings"

	glob "github.com/ryanuber/go-glob"
)

// Permissions structure for groups and users
type Permissions struct {
	WhitelistedIndices []Index `yaml:"whitelisted_indices"`
	WhitelistedAPIs    []API   `yaml:"whitelisted_apis"`
	CanManage          bool    `yaml:"can_manage"`
}

// Index struct defines index and REST verbs allowed
type Index struct {
	Name      string
	RESTverbs []string `yaml:"rest_verbs"`
}

// API struct defines index and REST verbs allowed
type API struct {
	Name      string
	RESTverbs []string `yaml:"rest_verbs"`
}

type requestContext struct {
	trace                   *Trace
	r                       *http.Request
	C                       *Config
	body                    []byte
	whitelistedIndices      []Index
	whitelistedIndicesNames string
	whitelistedAPIs         []API
	indices                 []string
	firstPathComponent      string
}

func getRequestContext(r *http.Request, C *Config, trace *Trace) (*requestContext, error) {
	body, err := getBody(r)
	if err != nil {
		return nil, err
	}
	bodyStr := string(body)
	trace.Body = bodyStr

	whitelistedIndices, err := getWhitelistedIndices(r, C)
	if err != nil {
		return nil, err
	}

	whitelistedAPIs, err := getWhitelistedAPIs(r, C)
	if err != nil {
		return nil, err
	}

	var indicesStrSlice []string
	for _, whitelistedIndex := range whitelistedIndices {
		indicesStrSlice = append(indicesStrSlice, whitelistedIndex.Name)
	}

	ctx := requestContext{
		trace:                   trace,
		r:                       r,
		C:                       C,
		body:                    body,
		whitelistedIndices:      whitelistedIndices,
		whitelistedAPIs:         whitelistedAPIs,
		whitelistedIndicesNames: strings.Join(indicesStrSlice, ","),
		firstPathComponent:      getFirstPathComponent(r),
	}

	return &ctx, nil
}

func (p *Prox) checkRBAC(ctx *requestContext) (bool, error) {

	user, err := getUser(ctx.r, ctx.C)
	if err != nil {
		return false, err
	}
	ctx.trace.User = user

	groups := getGroups(ctx.r, ctx.C)
	ctx.trace.Groups = groups

	ok, err := apiPermitted(ctx)
	if err != nil || !ok {
		return false, err
	}

	ok, err = indexPermitted(ctx)
	if err != nil || !ok {
		return false, err
	}

	return true, nil
}

func canManage(r *http.Request, C *Config) (bool, error) {
	groups := getGroups(r, C)

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

func getGroups(r *http.Request, C *Config) []string {
	// Group is trusted input provided by a SSO proxy layer
	var groups = []string{C.AnonymousGroup}
	if _, ok := r.Header[C.GroupHeaderName]; ok {
		rawGroups := r.Header[C.GroupHeaderName][0]
		switch groupType := C.GroupHeaderType; groupType {
		case "AD":
			groups = getAdGroups(rawGroups)
		case "space-delimited":
			groups = getSpaceDelimitedGroups(rawGroups)
		default:
			groups = []string{C.AnonymousGroup}
		}
	}
	return groups
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

func getSpaceDelimitedGroups(rawGroups string) []string {
	groups := strings.Split(rawGroups, " ")
	return groups
}

func getWhitelistedIndices(r *http.Request, C *Config) ([]Index, error) {
	var indices []Index
	groups := getGroups(r, C)

	for _, group := range groups {
		if configGroup, ok := C.RBAC.Groups[group]; ok {
			for _, configIndex := range configGroup.WhitelistedIndices {
				indices = append(indices, configIndex)
			}
		}
	}

	return indices, nil
}

func getWhitelistedAPIs(r *http.Request, C *Config) ([]API, error) {
	var apis []API
	groups := getGroups(r, C)

	for _, group := range groups {
		if configGroup, ok := C.RBAC.Groups[group]; ok {
			for _, configAPI := range configGroup.WhitelistedAPIs {
				apis = append(apis, configAPI)
			}
		}
	}

	return apis, nil
}

func getFirstPathComponent(r *http.Request) string {
	return strings.Split(r.URL.Path, "/")[1]
}

func apiPermitted(ctx *requestContext) (bool, error) {
	api := extractAPI(ctx.r)

	if len(api) > 0 {
		for _, whitelistedAPI := range ctx.whitelistedAPIs {
			// match API patterns in the RBAC config against patterns
			// that were extracted (both support globs)
			if glob.Glob(whitelistedAPI.Name, api) {
				// also enforce REST verbs that are permitted on the API
				if stringInSlice(ctx.r.Method, whitelistedAPI.RESTverbs) {
					return true, nil
				}
			}
		}
		return false, nil
	}
	return true, nil
}

func indexPermitted(ctx *requestContext) (bool, error) {

	if ctx.firstPathComponent == "_all" ||
		ctx.firstPathComponent == "_search" ||
		ctx.firstPathComponent == "*" {
		mutatePath(ctx)
	}

	indices, err := extractIndices(ctx)
	if err != nil {
		return false, err
	}

	var allowedIndices []string

	// support searching wild card indices
	// req'd by Kibana Visual Builder
	// this implementation is gross
	for i, index := range indices {
		if index == "*" {
			err := mutateWildcardIndexInBody(ctx)
			if err != nil {
				return false, err
			}
			indices[i] = ctx.whitelistedIndicesNames
			allowedIndices = append(allowedIndices, ctx.whitelistedIndicesNames)
		}
	}

	// if this request operates on any indices, apply RBAC logic
	if len(indices) > 0 {
		for _, whitelistedIndex := range ctx.whitelistedIndices {
			for _, index := range indices {
				// match index patterns in the RBAC config against patterns
				// that were extracted (both support globs)
				if glob.Glob(whitelistedIndex.Name, index) {
					// also enforce REST verbs that are permitted on the index
					if stringInSlice(ctx.r.Method, whitelistedIndex.RESTverbs) {
						allowedIndices = append(allowedIndices, index)
					}
				}
			}
		}
	} else {
		return true, nil
	}

	if len(allowedIndices) >= len(indices) {
		return true, nil
	}
	return false, nil
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
