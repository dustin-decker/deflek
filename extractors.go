package main

import (
	"bytes"
	"encoding/json"
	"strings"
)

func extractIndices(ctx requestContext) ([]string, error) {
	var indices []string

	body, err := getBody(ctx.r)
	if err != nil {
		return indices, err
	}
	ctx.trace.Body = string(body)

	ib, err := extractBodyIndices(ctx.api, body)
	if err != nil {
		return indices, err
	}
	if len(ib) > 0 {
		indices = append(indices, ib...)
	}
	ctx.indices = indices
	ctx.trace.Indices = indices

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

type mgetBody struct {
	Docs []struct {
		// XXX: Fill in as needed ...
		Index string `json:"_index"`
		// XXX: ...
	} `json:"docs"`
}

type msearchBody struct {
	// XXX: Fill in as needed ...
	Index string `json:"index"`
	// XXX: ...
}

type msearchBodyArray struct {
	// XXX: Fill in as needed ...
	Index []string `json:"index"`
	// XXX: ...
}

func extractBodyIndices(api string, body []byte) ([]string, error) {
	var indices []string

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

	var mgB mgetBody
	json.Unmarshal(body, &mgB)
	for _, doc := range mgB.Docs {
		if doc.Index != "" {
			indices = append(indices, strings.Split(doc.Index, ",")...)
		}
	}

	return indices, nil
}

func extractURIindices(ctx requestContext) ([]string, error) {
	var indices []string
	if len(ctx.api) > 1 && !strings.HasPrefix(ctx.api, "_") {
		indices = strings.Split(ctx.api, ",")
	}

	return indices, nil
}
