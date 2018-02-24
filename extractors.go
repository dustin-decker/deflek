package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
)

// extract indices from the incoming request
func extractIndices(ctx *requestContext) ([]string, error) {
	var indices []string

	// extract the indices specified in the body, which can be
	// specified in many different ways depending on the API :[
	ib, err := extractBodyIndices(ctx.firstPathComponent, ctx.body)
	if err != nil {
		return indices, err
	}
	if len(ib) > 0 {
		indices = append(indices, ib...)
	}
	ctx.indices = indices
	ctx.trace.Access = indices

	// extract indices from te URI path
	iu, err := extractURIindices(ctx.r)
	if err != nil {
		return indices, err
	}
	if len(iu) > 0 {
		indices = append(indices, iu...)
	}
	ctx.indices = indices
	ctx.trace.Access = indices

	return indices, nil
}

// multi document get can hit many different indices
// in the request body. get 'em all here
type mgetBody struct {
	Docs []struct {
		// XXX: Fill in as needed ...
		Index string `json:"_index"`
		// XXX: ...
	} `json:"docs"`
}

// older versions of kibana use this format
type msearchBodyString struct {
	// XXX: Fill in as needed ...
	Index string `json:"index"`
	// XXX: ...
}

// newer version of kibana use this format
type msearchBodyArray struct {
	// XXX: Fill in as needed ...
	Index []string `json:"index"`
	// XXX: ...
}

type bulk struct {
	Index string `json:"_index"`
}

// extract indices from the incoming request body
func extractBodyIndices(api string, body []byte) ([]string, error) {
	var indices []string

	// special case here.
	// bulk API problably does this too, but I haven't gotten to that yet
	// NDJSON. Savages.
	JSONs := bytes.Split(body, []byte("\n"))
	for _, JSON := range JSONs {

		// attempt older string syntax
		var msB msearchBodyString
		json.Unmarshal(JSON, &msB)

		if msB.Index != "" {
			indices = append(indices, strings.Split(msB.Index, ",")...)
		}

		// attempt newer array syntax
		var msBA msearchBodyArray
		json.Unmarshal(JSON, &msBA)

		if len(msBA.Index) > 0 {
			for _, index := range msBA.Index {
				indices = append(indices, strings.Split(index, ",")...)
			}
		}

		// bulk API
		m := map[string]bulk{}
		json.Unmarshal(JSON, &m)
		for _, v := range m {
			if len(v.Index) > 0 {
				indices = append(indices, strings.Split(v.Index, ",")...)
			}
		}

	}

	// extract indices from the way of mget
	var mgB mgetBody
	json.Unmarshal(body, &mgB)
	for _, doc := range mgB.Docs {
		if doc.Index != "" {
			indices = append(indices, strings.Split(doc.Index, ",")...)
		}
	}

	return indices, nil
}

// extract indices that are specified in the URI
func extractURIindices(r *http.Request) ([]string, error) {
	index := getFirstPathComponent(r)
	var indices []string
	if len(index) > 1 && !strings.HasPrefix(index, "_") {
		indices = strings.Split(index, ",")
	}

	return indices, nil
}

// extract API that are specified in the URI
func extractAPI(r *http.Request) string {
	api := getFirstPathComponent(r)
	if len(api) > 1 {
		for _, elem := range strings.Split(r.URL.Path, "/") {
			if strings.HasPrefix(elem, "_") {
				return elem
			}
		}
	}

	return ""
}
