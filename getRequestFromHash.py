from elasticsearch import Elasticsearch
import json, requests
import re
import base64

# Python dictionary object representing an Elasticsearch JSON query:
#def getReqFromHash(hash):
def getReqFromHash(esServer, esIndex, hash):
	elastic_client = Elasticsearch(str(esServer))
	search_param = {
		"track_total_hits": False,
		"sort": [
			{
				"timestamp": {
					"order": "desc",
					"unmapped_type": "boolean"
				}
			}
		],
		"fields": [
			{
				"field": "*",
				"include_unmapped": "true"
			},
			{
				"field": "response.cookies.expiration",
				"format": "strict_date_optional_time"
			},
			{
				"field": "timestamp",
				"format": "strict_date_optional_time"
			}
		],
		"size": 1,
		"version": True,
		"script_fields": {},
		"stored_fields": [
			"*"
		],
		"runtime_mappings": {},
		"_source": False,
		"query": {
			"bool": {
				"must": [],
				"filter": [
					{
						"match_phrase": {
							"hashes": "0"
						}
					}
				],
				"should": [],
				"must_not": []
			}
		},
		"highlight": {
			"pre_tags": [
				"@kibana-highlighted-field@"
			],
			"post_tags": [
				"@/kibana-highlighted-field@"
			],
			"fields": {
				"*": {}
			},
			"fragment_size": 2147483647
		}
	}
	search_param['query']['bool']['filter'][0]['match_phrase']['hashes'] = str(hash)
	res = elastic_client.search(index=str(esIndex), body=search_param)
	res_base64=re.findall("(?<=\'request.asBase64': \[u').*?(?='\]\}\,)",str(res))
	if len(res_base64) == 0:
		return "empty"
	else:
		req = base64.b64decode(res_base64[0]).decode("utf-8")
		return req
