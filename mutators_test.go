package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMutatePath(t *testing.T) {
	ctx, err := getTestContext("/_all/_search", "", "GET")
	if err != nil {
		t.Error("could not get context: ", err)
	}

	mutatePath(ctx)

	expected := "/test_deflek,test_deflek2,globby-*/_search"

	if ctx.r.URL.Path != expected {
		t.Errorf("got %v, expected %v", ctx.r.URL.Path, expected)
	}
}

func TestMutateWildcardIndexInBody(t *testing.T) {
	body := `{"index":"*","ignore":[404],"timeout":"90s","requestTimeout":90000,"ignoreUnavailable":true}
{"size":0,"query":{"bool":{"must":[{"range":{"@timestamp":{"gte":1519223869113,"lte":1519225669114,"format":"epoch_millis"}}},{"bool":{"must":[{"match_all":{}}],"must_not":[]}}]}},"aggs":{"61ca57f1-469d-11e7-af02-69e470af7417":{"filter":{"match_all":{}},"aggs":{"timeseries":{"date_histogram":{"field":"@timestamp","interval":"30s","min_doc_count":0,"time_zone":"America/Chicago","extended_bounds":{"min":1519223869113,"max":1519225669114}},"aggs":{"61ca57f2-469d-11e7-af02-69e470af7417":{"bucket_script":{"buckets_path":{"count":"_count"},"script":{"inline":"count * 1","lang":"expression"},"gap_policy":"skip"}}}}}}}}
`

	ctx, err := getTestContext("/_msearch", body, "GET")
	if err != nil {
		t.Error("could not get context: ", err)
	}

	mutateWildcardIndexInBody(ctx)

	mutatedBody, _ := getBody(ctx.r)

	expectedBody := `{"index":"test_deflek,test_deflek2,globby-*,.kibana","ignore":[404],"timeout":"90s","requestTimeout":90000,"ignoreUnavailable":true}
{"size":0,"query":{"bool":{"must":[{"range":{"@timestamp":{"gte":1519223869113,"lte":1519225669114,"format":"epoch_millis"}}},{"bool":{"must":[{"match_all":{}}],"must_not":[]}}]}},"aggs":{"61ca57f1-469d-11e7-af02-69e470af7417":{"filter":{"match_all":{}},"aggs":{"timeseries":{"date_histogram":{"field":"@timestamp","interval":"30s","min_doc_count":0,"time_zone":"America/Chicago","extended_bounds":{"min":1519223869113,"max":1519225669114}},"aggs":{"61ca57f2-469d-11e7-af02-69e470af7417":{"bucket_script":{"buckets_path":{"count":"_count"},"script":{"inline":"count * 1","lang":"expression"},"gap_policy":"skip"}}}}}}}}
`

	if diff := cmp.Diff(expectedBody, string(mutatedBody)); diff != "" {
		t.Errorf("unexpected difference: (-got +want)\n%s", diff)
	}
}
