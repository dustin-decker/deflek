package main

import (
	"bytes"
	"encoding/json"
	"strings"
)

// extract indices from the incoming request
func extractIndices(ctx requestContext) ([]string, error) {
	var indices []string

	body, err := getBody(ctx.r)
	if err != nil {
		return indices, err
	}
	ctx.trace.Body = string(body)

	// extract the indices specified in the body, which can be
	// specified in many different ways depending on the API :[
	ib, err := extractBodyIndices(ctx.api, body)
	if err != nil {
		return indices, err
	}
	if len(ib) > 0 {
		indices = append(indices, ib...)
	}
	ctx.indices = indices
	ctx.trace.Indices = indices

	// extract indices from te URI path
	iu, err := extractURIindices(ctx)
	if err != nil {
		return indices, err
	}
	if len(iu) > 0 {
		indices = append(indices, iu...)
	}
	ctx.indices = indices
	ctx.trace.Indices = indices

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
type msearchBody struct {
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

// extract indices from the incoming request body
func extractBodyIndices(api string, body []byte) ([]string, error) {
	var indices []string

	// special case here.
	// this API uses a JSON blob on each line
	// bulk API problably does this too, but I haven't gotten to that yet
	if api == "_msearch" {
		// NDJSON. Savages.
		JSONs := bytes.Split(body, []byte("\n"))
		for _, JSON := range JSONs {
			var msB msearchBody
			json.Unmarshal(JSON, &msB)

			if msB.Index != "" {
				indices = append(indices, strings.Split(msB.Index, ",")...)
			}

			var msBA msearchBodyArray
			json.Unmarshal(JSON, &msBA)

			if len(msBA.Index) > 0 {
				for _, index := range msBA.Index {
					indices = append(indices, strings.Split(index, ",")...)
				}
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
func extractURIindices(ctx requestContext) ([]string, error) {
	var indices []string
	if len(ctx.api) > 1 && !strings.HasPrefix(ctx.api, "_") {
		indices = strings.Split(ctx.api, ",")
	}

	return indices, nil
}
