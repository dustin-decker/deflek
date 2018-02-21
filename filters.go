package main

// // req'd by Visual Builder
// if ctx.r.URL.Path == "/*/_field_stats" {
// 	return true, nil
// }

// TODO for Visual Builder
// Replace * with all indices they have access to... :(
//  {"code":403,"elasped":0,"groups":"[group2]","index":"[*]","lvl":"eror","method":"POST","msg":"* not in index whitelist","path":"/_msearch","query":"{\"index\":[\"*\"],\"ignore\":[404],\"timeout\":\"90s\",\"requestTimeout\":90000,\"ignoreUnavailable\":true}\n{\"size\":0,\"query\":{\"bool\":{\"must\":[{\"range\":{\"@timestamp\":{\"gte\":1339990677678,\"lte\":1497152277679,\"format\":\"epoch_millis\"}}},{\"bool\":{\"must\":[{\"query_string\":{\"query\":\"*\"}}],\"must_not\":[]}}]}},\"aggs\":{\"ec3c3e41-53d5-11e7-80ea-7bfec2933998\":{\"filter\":{\"match_all\":{}},\"aggs\":{\"timeseries\":{\"date_histogram\":{\"field\":\"@timestamp\",\"interval\":\"604800s\",\"min_doc_count\":0,\"extended_bounds\":{\"min\":1339990677678,\"max\":1497152277679}},\"aggs\":{\"ec3c3e42-53d5-11e7-80ea-7bfec2933998\":{\"bucket_script\":{\"buckets_path\":{\"count\":\"_count\"},\"script\":{\"inline\":\"count * 1\",\"lang\":\"expression\"},\"gap_policy\":\"skip\"}}}}}}}}\n","t":"2017-06-18T03:37:57.786407134Z","user":""}

// fmt.Println(ctx.whitelistedIndices)
// for _, whitelistedIndex := range ctx.whitelistedIndices {
// 	for _, index := range ctx.indices {
// 		if glob.Glob(whitelistedIndex.Name, index) {
// 			return true, nil
// 		}
// 	}
// }
// return false, nil

// }
