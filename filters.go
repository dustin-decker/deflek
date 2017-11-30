package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	glob "github.com/ryanuber/go-glob"
)

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

func filterNamedIndex(ctx requestContext) (bool, error) {
	// Index API endpoints begin with the index name
	// Other API endpoints begin with '_'

	ctx.trace.Index = []string{ctx.index}
	if ctx.r.Method == "POST" {
		body, err := getBody(ctx.r)
		if err != nil {
			return false, err
		}
		ctx.trace.Query = string(body)
	}

	// req'd by Visual Builder
	if ctx.r.URL.Path == "/*/_field_stats" {
		return true, nil
	}

	// TODO for Visual Builder
	// Replace * with all indices they have access to... :(
	//  {"code":403,"elasped":0,"groups":"[group2]","index":"[*]","lvl":"eror","method":"POST","msg":"* not in index whitelist","path":"/_msearch","query":"{\"index\":[\"*\"],\"ignore\":[404],\"timeout\":\"90s\",\"requestTimeout\":90000,\"ignoreUnavailable\":true}\n{\"size\":0,\"query\":{\"bool\":{\"must\":[{\"range\":{\"@timestamp\":{\"gte\":1339990677678,\"lte\":1497152277679,\"format\":\"epoch_millis\"}}},{\"bool\":{\"must\":[{\"query_string\":{\"query\":\"*\"}}],\"must_not\":[]}}]}},\"aggs\":{\"ec3c3e41-53d5-11e7-80ea-7bfec2933998\":{\"filter\":{\"match_all\":{}},\"aggs\":{\"timeseries\":{\"date_histogram\":{\"field\":\"@timestamp\",\"interval\":\"604800s\",\"min_doc_count\":0,\"extended_bounds\":{\"min\":1339990677678,\"max\":1497152277679}},\"aggs\":{\"ec3c3e42-53d5-11e7-80ea-7bfec2933998\":{\"bucket_script\":{\"buckets_path\":{\"count\":\"_count\"},\"script\":{\"inline\":\"count * 1\",\"lang\":\"expression\"},\"gap_policy\":\"skip\"}}}}}}}}\n","t":"2017-06-18T03:37:57.786407134Z","user":""}

	for _, whitelistedIndex := range ctx.whitelistedIndices {
		if glob.Glob(whitelistedIndex.Name, ctx.index) {
			for _, method := range whitelistedIndex.RESTverbs {
				if ctx.r.Method == method {
					return true, nil
				}
			}
			return false, errors.New("Method not allowed on index")
		}
	}
	return false, errors.New("Index not allowed")

}
