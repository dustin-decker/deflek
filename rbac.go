package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	glob "github.com/ryanuber/go-glob"
)

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

	// canManage, err := canManage(r, C)
	// if err != nil {
	// 	return false, err
	// }

	fmt.Println(trace.Groups)

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

type requestContext struct {
	trace              *AppTrace
	r                  *http.Request
	c                  *Config
	whitelistedIndices []Index
	index              string
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

	// this needs to be revisited. doesn't seem correct
	case index == "_msearch":
		filterMsearch(ctx)

	case index == "_mget":
		body, _ := getBody(r)
		trace.Query = string(body)
		return false, errors.New("Searching with mget is not supported at this time")

	case !strings.HasPrefix(index, "_") && len(index) > 0:
		filterNamedIndex(ctx)

	}
	return true, nil
}
