package main

import (
	"net/url"
	"strings"
)

func mutateRequest(ctx requestContext) {
	var indices []string
	for _, whitelistedIndex := range ctx.whitelistedIndices {
		if !strings.HasPrefix(whitelistedIndex.Name, ".") {
			indices = append(indices, whitelistedIndex.Name)
		}
	}
	indicesAsURI := strings.Join(indices, ",")
	api := ctx.api
	api = strings.TrimPrefix(api, "/_all")
	urlStr := "/" + indicesAsURI + ctx.r.URL.EscapedPath()
	reqURL, _ := url.Parse(urlStr)
	ctx.r.URL = reqURL
}
