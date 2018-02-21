package main

import (
	"testing"
)

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func TestExtractBodyMsearch(t *testing.T) {
	// based on the docs example. modified to include two indices
	// https://www.elastic.co/guide/en/elasticsearch/reference/current/search-multi-search.html
	body := `
{"index" : "test"}
{"query" : {"match_all" : {}}, "from" : 0, "size" : 10}
{"index" : "test2", "search_type" : "dfs_query_then_fetch"}
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
