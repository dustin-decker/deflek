package main

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetWhitelistedIndices(t *testing.T) {

	expectedIndices := []Index{
		Index{Name: "test_deflek",
			RESTverbs: []string{
				"GET", "POST",
			}},
		Index{Name: "test_deflek2",
			RESTverbs: []string{
				"GET",
			}},
		Index{Name: "globby-*",
			RESTverbs: []string{
				"GET",
			}},
		Index{Name: ".kibana",
			RESTverbs: []string{
				"GET", "POST",
			}},
	}

	var c Config
	c.getConf()

	req, _ := http.NewRequest("GET", "http://localhost:9200/_cluster/health", nil)
	req.Header.Add("X-Remote-User", "dustind")
	req.Header.Add("X-Remote-Groups", "OU=thing,CN=group2,DC=something")

	extractedIndices, err := getWhitelistedIndices(req, &c)
	if err != nil {
		t.Error("got error while getting whitelisted indices: ", err)
	}

	if diff := cmp.Diff(expectedIndices, extractedIndices); diff != "" {
		t.Errorf("unexpected difference: (-got +want)\n%s", diff)
	}
}

func indexInSlice(a Index, indices []Index) bool {
	for _, b := range indices {
		if b.Name == a.Name {
			return true
		}
	}
	return false
}
