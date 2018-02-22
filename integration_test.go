package main

// these tests require the current build of deflek running with
// the included `config.example.yaml` file and pointed to an ES
// instance

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

// custom RoundTrip injects authentication headers into the test client
func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// NOTE: this client is configured for the `config.example.yaml` included
	//
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

	testIndices := []string{
		"test_deflek",
		"test_deflek2",
		"secret_stuff",
		"globby-test"}

	indexCreateBody := `
{
	"settings" : {
		"index" : {
			"number_of_shards" : 1, 
			"number_of_replicas" : 0 
		}
	}
}`
	for _, index := range testIndices {
		exists, err := c.IndexExists(index).Do(ctx)
		if err != nil {
			log.Fatal(err)
		}
		if !exists {
			c.CreateIndex(index).Body(indexCreateBody).Do(ctx)
			c.Index().Index(index).Id("1").OpType("index").Do(ctx)
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

	res, err := httpC.Post(base+"/_mget", "application/json",
		bytes.NewBuffer([]byte(body)))
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

	// test on index literal
	res, err := httpC.Post(base+"/test_deflek2/_search?q=tag:wow",
		"application/json", bytes.NewBuffer([]byte("{}")))
	if err != nil {
		log.Fatal(err)
	}
	testBlocked(t, res)

	// test on glob patterns
	res, err = httpC.Post(base+"/globby-te*/_search?q=tag:wow",
		"application/json",
		bytes.NewBuffer([]byte("{}")))
	if err != nil {
		log.Fatal(err)
	}
	testBlocked(t, res)
}

func TestRESTverbAllow(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	// test on index literal
	res, err := httpC.Post(base+"/test_deflek/_search?q=tag:wow",
		"application/json", bytes.NewBuffer([]byte("{}")))
	if err != nil {
		log.Fatal(err)
	}
	testAllowed(t, res)

	// test on glob patterns
	res, err = httpC.Get(base + "/globby-t*/_search?q=tag:wow")
	if err != nil {
		log.Fatal(err)
	}
	testAllowed(t, res)
}

func TestGlobURI(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	res, err := httpC.Get(base + "/globby-te*/_search?q=tag:wow")
	if err != nil {
		log.Fatal(err)
	}

	testAllowed(t, res)
}

func TestWildcardIndexMutator(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	body := `
{"index":"*","ignore":[404],"timeout":"90s","requestTimeout":90000,"ignoreUnavailable":true}
{"size":0,"query":{"bool":{"must":[{"range":{"@timestamp":{"gte":1519223869113,"lte":1519225669114,"format":"epoch_millis"}}},{"bool":{"must":[{"match_all":{}}],"must_not":[]}}]}},"aggs":{"61ca57f1-469d-11e7-af02-69e470af7417":{"filter":{"match_all":{}},"aggs":{"timeseries":{"date_histogram":{"field":"@timestamp","interval":"30s","min_doc_count":0,"time_zone":"America/Chicago","extended_bounds":{"min":1519223869113,"max":1519225669114}},"aggs":{"61ca57f2-469d-11e7-af02-69e470af7417":{"bucket_script":{"buckets_path":{"count":"_count"},"script":{"inline":"count * 1","lang":"expression"},"gap_policy":"skip"}}}}}}}}
`

	res, err := httpC.Post(base+"/_msearch", "application/json", bytes.NewBuffer([]byte(body)))
	if err != nil {
		log.Fatal(err)
	}

	testAllowed(t, res)
}

func TestWildcardURImutator(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	res, err := httpC.Get(base + "/*/_search?q=tag:wow")
	if err != nil {
		log.Fatal(err)
	}

	testAllowed(t, res)
}
