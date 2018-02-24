package main

import (
	"net/http"
	"net/url"
	"testing"
)

func TestExtractURIindices(t *testing.T) {
	var req http.Request
	req.URL, _ = url.Parse("http://localhost:9200/test1,test2/_search?q=tag:wow")

	indices, err := extractURIindices(&req)
	if err != nil {
		t.Error("couldn't extract URI indices, got: ", err)
	}

	if !stringInSlice("test1", indices) {
		t.Error("expected 'test' in indices, got: ", indices)
	}

	if !stringInSlice("test2", indices) {
		t.Error("expected 'test' in indices, got: ", indices)
	}
}

func TestExtractBodyMsearch(t *testing.T) {
	// based on the docs example. modified to include two indices
	// https://www.elastic.co/guide/en/elasticsearch/reference/current/search-multi-search.html
	// added array syntax
	body := `
{"index" : "test"}
{"query" : {"match_all" : {}}, "from" : 0, "size" : 10}
{"index" : ["test2","test3"], "search_type" : "dfs_query_then_fetch"}
{"query" : {"match_all" : {}}}
{}
{"query" : {"match_all" : {}}}

{"query" : {"match_all" : {}}}
{"search_type" : "dfs_query_then_fetch"}
{"query" : {"match_all" : {}}}
`

	indices, err := extractBodyIndices("_msearch", []byte(body))
	if err != nil {
		t.Error("failed to extract body: ", err)
	}

	if !stringInSlice("test", indices) {
		t.Error("expected 'test' in indices, got: ", indices)
	}

	if !stringInSlice("test2", indices) {
		t.Error("expected 'test' in indices, got: ", indices)
	}

	if !stringInSlice("test3", indices) {
		t.Error("expected 'test' in indices, got: ", indices)
	}
}

func TestExtractBodyMget(t *testing.T) {
	// based on the docs example. modified to include two indices
	// https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-multi-get.html
	body := `
{
	"docs" : [
		{
			"_index" : "test",
			"_id" : "1"
		},
		{
			"_index" : "test2",
			"_id" : "2"
		}
	]
}
`

	indices, err := extractBodyIndices("_mget", []byte(body))
	if err != nil {
		t.Error("failed to extract body: ", err)
	}

	if !stringInSlice("test", indices) {
		t.Error("expected 'test' in indices, got: ", indices)
	}

	if !stringInSlice("test2", indices) {
		t.Error("expected 'test2' in indices, got: ", indices)
	}
}

func TestExtractAPI(t *testing.T) {
	ctx, err := getTestContext("/_nodes/local", "")
	if err != nil {
		t.Error("could not get context: ", err)
	}
	api := extractAPI(ctx.r)
	if api != "_nodes" {
		t.Errorf("got %s, expected %s", api, "_nodes")
	}

	ctx, err = getTestContext("/some_index/local", "")
	if err != nil {
		t.Error("could not get context: ", err)
	}
	api = extractAPI(ctx.r)
	if api != "" {
		t.Errorf("got %s, expected %s", api, "")
	}

	ctx, err = getTestContext("/some_index/_search", "")
	if err != nil {
		t.Error("could not get context: ", err)
	}
	api = extractAPI(ctx.r)
	if api != "_search" {
		t.Errorf("got %s, expected %s", api, "_search")
	}
}
