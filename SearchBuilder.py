import json, requests
import re

def getReqFromAS(esServer, esIndex, query):
	url = esServer + "/" + esIndex + "/_search/?q="
	res = requests.get(url+str(query))
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
	except:
		return "Error"