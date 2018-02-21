package main

import (
	"bytes"
	"io/ioutil"
	"net/url"
	"regexp"
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
	escapedPath := ctx.r.URL.EscapedPath()
	escapedPath = strings.TrimPrefix(escapedPath, "/_all")
	urlStr := "/" + indicesAsURI + escapedPath
	reqURL, _ := url.Parse(urlStr)
	ctx.r.URL = reqURL
}

func mutateWildcardIndexInBody(ctx requestContext) error {
	// this is gross
	body, err := getBody(ctx.r)
	if err != nil {
		return err
	}
	re := regexp.MustCompile(`\"\*\"`)
	cleanIndex := `"` + ctx.whitelistedIndicesNames + `"`
	cleanBody := re.ReplaceAllString(string(body), cleanIndex)
	ctx.r.Body = ioutil.NopCloser(bytes.NewReader([]byte(cleanBody)))
	ctx.r.ContentLength = int64(len([]byte(cleanBody)))
	ctx.trace.Body = cleanBody

	return nil
}
