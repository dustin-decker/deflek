package main

import (
	"context"
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

	testIndices := []string{"test_deflek", "secret_stuff"}
	for _, index := range testIndices {
		exists, err := c.IndexExists(index).Do(ctx)
		if err != nil {
			log.Fatal(err)
		}
		if !exists {
			c.CreateIndex(index).Do(ctx)
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

const base = "http://127.0.0.1:8080"

func TestAll(t *testing.T) {
	createEsClient()
	httpC := createHTTPClient()

	// ctx := context.Background()
	// termQuery := elastic.NewTermQuery("user", "dustind")
	// _, err := c.Search().Index("_all").Query(termQuery).Do(ctx)
	// if !elastic.IsStatusCode(err, 401) {
	// 	t.Error("request should have been disallowed")
	// }

	res, err := httpC.Get(base + "/_all/tweet/_search?q=tag:wow")
	if err != nil {
		log.Fatal(err)
	}

	if res.StatusCode != 401 {
		t.Error("request should have been disallowed", res.StatusCode)
	}
}
