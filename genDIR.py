# -*- coding: utf-8 -*-
from elasticsearch import Elasticsearch
import re
from urllib.parse import urlparse


def List2String(a):
	b='/'.join(a)
	return str(b)

elastic_client = Elasticsearch('http://10.14.140.134:9200',headers={"Content-Type": "application/json"})  # Sửa IP


# Python dictionary object representing an Elasticsearch JSON query:
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
	"size": 500,
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
					"bool": {
						"should": [
							{
								"exists": {
									"field": "request.requestline"
								}
							}
						],
						"minimum_should_match": 1
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

res = elastic_client.search(index="wase-thread", body=search_param) #Sửa index

#(?<=POST).*?(?=HTTP\/(2|1\.1)) and (?<=GET).*?(?=HTTP\/(2|1\.1))
res_POST=re.findall("(?<=\'request.requestline': \['POST ).*?(?=HTTP\/)",str(res))
res_GET=re.findall("(?<=\'request.requestline': \['GET ).*?(?=HTTP\/)",str(res))
res_All=res_POST + res_GET
# print('\n'.join(res_All))
with open("DIR.txt","a+") as file:
	file.seek(0)
	read_all=file.read()
	for i in range(0,len(res_All)):
		parsed_url = urlparse(str(res_All[i]))
		path = parsed_url.path
		if path in read_all:
			next
		else:
			read_all+=path
			file.write(str(path)+"\n")
file.close()