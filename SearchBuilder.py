import json, requests
import re
from elasticsearch import Elasticsearch
import urllib
import json
def getRawFromApi(kibanaServer,query):
	return requests.get(kibanaServer+"/api/query/gen?query="+urllib.quote(query)).text


def getReqFromAS(kibanaServer,esServer, esIndex, query):
	raw= getRawFromApi(kibanaServer,query)
	header = {"Content-Type":"application/json"}
	a = requests.post(esServer+"/"+esIndex+"/_search",headers=header,data=raw)
	b = a.json()
	total=b.get('hits').get("total").get("value")
	res = requests.post(esServer+"/"+esIndex+"/_search?size="+str(total),headers=header,data=raw)
	try:
		
		res_dict = res.json()
		res_len = len(res_dict.get('hits').get('hits'))
		data = []
		for i in range(0,res_len):
			unit = []
			method = res_dict.get('hits').get('hits')[i].get('_source').get('request').get('method')
			host = res_dict.get('hits').get('hits')[i].get('_source').get('host')
			get_path = res_dict.get('hits').get('hits')[i].get('_source').get('request').get('requestline')
			path = get_path.split(" ")[1]
			status_code = res_dict.get('hits').get('hits')[i].get('_source').get('response').get('status')
			reqAsBase64 = res_dict.get('hits').get('hits')[i].get('_source').get('request').get('asBase64')
			resAsBase64 = res_dict.get('hits').get('hits')[i].get('_source').get('response').get('asBase64')
			unit.append(i+1)
			unit.append(method)
			unit.append(host)
			unit.append(path)
			unit.append(status_code)
			unit.append(reqAsBase64)
			unit.append(resAsBase64)
			data.append(unit)
		return data
	except Exception as e:
		print(e)
		return "Error"