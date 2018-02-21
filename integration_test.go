package main

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/olivere/elastic"
)

type authTransport struct {
	Transport http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("X-Remote-User", "dustind")
	req.Header.Add("X-Remote-Groups", "OU=thing,CN=group2,DC=something")
	tr := &http.Transport{}
	res, err := tr.RoundTrip(req)
	return res, err
}

func createEsClient() *elastic.Client {
	ctx := context.Background()
	url := "http://127.0.0.1:8080"
	sniff := true

	httpClient := &http.Client{
		Transport: &authTransport{},
		Timeout:   10 * time.Second,
	}

	c, err := elastic.NewClient(elastic.SetURL(url),
		elastic.SetSniff(sniff),
		elastic.SetHttpClient(httpClient))
	if err != nil {
		log.Fatal(err)
	}

	testIndices := []string{"test_deflek", "test_deflek2", "secret_stuff"}
	for _, index := range testIndices {
		exists, err := c.IndexExists(index).Do(ctx)
		if err != nil {
			log.Fatal(err)
		}
		if !exists {
			c.CreateIndex(index).Do(ctx)
			c.Index().Index("secret_stuff").Id("1").OpType("index")
			c.Index().Index("test_deflek").Id("1").OpType("index")
			c.Index().Index("test_deflek2").Id("1").OpType("index")
		}
	}
	return c
}

func createHTTPClient() *http.Client {
	httpClient := &http.Client{
		Transport: &authTransport{},
		Timeout:   5 * time.Second,
	}
	return httpClient
}

func testAllowed(t *testing.T, res *http.Response) {
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error("couldn't read the body. got: ", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("request should have been allowed. got: \n status code: %v \nbody: %s", res.StatusCode, string(body))
	}
}

func testBlocked(t *testing.T, res *http.Response) {
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error("couldn't read the body. got: ", err)
	}
	if res.StatusCode != 401 {
		t.Errorf("request should have been blocked. got: \n status code: %v \nbody: %s", res.StatusCode, string(body))
	}
}

const base = "http://127.0.0.1:8080"

func TestAll(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	res, err := httpC.Get(base + "/_all/_search?q=tag:wow")
	if err != nil {
		log.Fatal(err)
	}

	testAllowed(t, res)
}

func TestSearch(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	res, err := httpC.Get(base + "/_search?q=tag:wow")
	if err != nil {
		log.Fatal(err)
	}

	testAllowed(t, res)
}

func TestMsearchBlocked(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	body := `
{"index" : "test_deflek"}
{"query" : {"match_all" : {}}, "from" : 0, "size" : 10}
{"index" : "secret_stuff", "search_type" : "dfs_query_then_fetch"}
{"query" : {"match_all" : {}}}
{}
{"query" : {"match_all" : {}}}

{"query" : {"match_all" : {}}}
{"search_type" : "dfs_query_then_fetch"}
{"query" : {"match_all" : {}}}
`

	res, err := httpC.Post(base+"/_msearch", "application/json", bytes.NewBuffer([]byte(body)))
	if err != nil {
		log.Fatal(err)
	}

	testBlocked(t, res)
}

func TestMsearchAllowed(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	body := `
{"index" : "test_deflek"}
{"query" : {"match_all" : {}}, "from" : 0, "size" : 10}
{"index" : "test_deflek", "search_type" : "dfs_query_then_fetch"}
{"query" : {"match_all" : {}}}
{}
{"query" : {"match_all" : {}}}

{"query" : {"match_all" : {}}}
{"search_type" : "dfs_query_then_fetch"}
{"query" : {"match_all" : {}}}
`

	res, err := httpC.Post(base+"/_msearch", "application/json", bytes.NewBuffer([]byte(body)))
	if err != nil {
		log.Fatal(err)
	}

	testAllowed(t, res)
}

func TestMgetBlocked(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	body := `
	{
		"docs" : [
			{
				"_index" : "test_deflek",
				"_id" : "1"
			},
			{
				"_index" : "secret_stuff",
				"_id" : "1"
			}
		]
	}	
	`

	res, err := httpC.Post(base+"/_mget", "application/json", bytes.NewBuffer([]byte(body)))
	if err != nil {
		log.Fatal(err)
	}

	testBlocked(t, res)
}

func TestMgetAllowed(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	body := `
	{
		"docs" : [
			{
				"_index" : "test_deflek",
				"_id" : "1"
			},
			{
				"_index" : "test_deflek",
				"_id" : "2"
			}
		]
	}	
	`

	res, err := httpC.Post(base+"/_mget", "application/json", bytes.NewBuffer([]byte(body)))
	if err != nil {
		log.Fatal(err)
	}

	testAllowed(t, res)
}

func TestNamedIndexBlock(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	res, err := httpC.Get(base + "/secret_stuff/_search?q=tag:wow")
	if err != nil {
		log.Fatal(err)
	}

	testBlocked(t, res)
}

func TestNamedIndexAllow(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	res, err := httpC.Get(base + "/test_deflek/_search?q=tag:wow")
	if err != nil {
		log.Fatal(err)
	}

	testAllowed(t, res)
}

func TestRESTverbBlock(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	res, err := httpC.Post(base+"/test_deflek2/_search?q=tag:wow",
		"application/json", bytes.NewBuffer([]byte("{}")))
	if err != nil {
		log.Fatal(err)
	}

	testBlocked(t, res)
}

func TestRESTverbAllow(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	res, err := httpC.Post(base+"/test_deflek/_search?q=tag:wow",
		"application/json", bytes.NewBuffer([]byte("{}")))
	if err != nil {
		log.Fatal(err)
	}

	testAllowed(t, res)
}

//// This might not be a thing in 6.X!
// func TestFieldStatsAllow(t *testing.T) {
// 	createEsClient()
// 	httpC := createHTTPClient()

// 	res, err := httpC.Post(base+"/*/_field_stats",
// 		"application/json",
// 		bytes.NewReader([]byte("{}")))
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	testAllowed(t, res)
// }
