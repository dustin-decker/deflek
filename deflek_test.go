package main

import (
	"context"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/olivere/elastic"
)

func createClient() *elastic.Client {
	ctx := context.Background()
	url := "http://127.0.0.1:8080"
	sniff := true
	c, err := elastic.NewClient(elastic.SetURL(url), elastic.SetSniff(sniff))
	if err != nil {
		log.Fatal(err)
	}

	testIndexName := "test_deflek"
	exists, err := c.IndexExists(testIndexName).Do(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if !exists {
		c.CreateIndex(testIndexName).Do(ctx)
	}
	return c
}

func TestAll(t *testing.T) {
	ctx := context.Background()
	c := createClient()
	termQuery := elastic.NewTermQuery("user", "dustind")
	_, err := c.Search().Index("_all").Query(termQuery).Do(ctx)
	if !elastic.IsStatusCode(err, 403) {
		t.Error("request should have been disallowed")
	}
}
