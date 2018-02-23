package main

import (
	"testing"
)

func TestMutatePath(t *testing.T) {
	ctx, err := getTestContext("/_all/_search")
	if err != nil {
		t.Error("could not get context: ", err)
	}

	mutatePath(ctx)

	expected := "/test_deflek,test_deflek2,globby-*/_search"

	if ctx.r.URL.EscapedPath() != expected {
		t.Errorf("got %v, expected %v", ctx.r.URL.EscapedPath(), expected)
	}
}
