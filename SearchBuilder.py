import requests
import urllib
import base64
from burp import IHttpService,IMessageEditorController
import traceback

def getRawFromApi(kibanaServer,query):
	return requests.get(kibanaServer+"/api/query/gen?query="+urllib.quote(query)).text

class service(IHttpService):
	def __init__(self,host1,port1,protocol1):
		self.host1 = host1
		self.port1 = port1
		self.protocol1 = protocol1
	def getHost(self):
		return self.host1
	def getPort(self):
		return self.port1
	def getProtocol(self):
		return self.protocol1

class requestResponse(IMessageEditorController):
	def __init__(self,host1,port1,protocol1,request,response):
		self.service1 = service(host1,port1,protocol1)
		self.request1 = request
		self.response1 = response
	def getRequest(self):
		return bytes(self.request1)
	def getResponse(self):
		return bytes(self.response1)
	def getHttpService(self):
		return self.service1
	def setRequest(self,req):
		pass
	def setResponse(self,res):
		pass


def getReqFromAS(self,kibanaServer,esServer, esIndex, query):
	raw= getRawFromApi(kibanaServer,query)
	header = {"Content-Type":"application/json"}
	resp = requests.post(esServer+"/"+esIndex+"/_search",headers=header,data=raw)
	b = resp.json()
	self._searchTable.clear()
	try:
		total=b.get('hits').get("total").get("value")
		res = requests.post(esServer+"/"+esIndex+"/_search?size="+str(total),headers=header,data=raw)
		res_dict = res.json()
		res_len = len(res_dict.get('hits').get('hits'))
		data = []
		for i in range(0,res_len):
			unit = []
			method = res_dict.get('hits').get('hits')[i].get('_source').get('request').get('method')
			host = res_dict.get('hits').get('hits')[i].get('_source').get('host')
			port = res_dict.get('hits').get('hits')[i].get('_source').get('port')
			status_code = res_dict.get('hits').get('hits')[i].get('_source').get('response').get('status')
			types = res_dict.get('hits').get('hits')[i].get('_source').get('types')
			reqAsBase64 = res_dict.get('hits').get('hits')[i].get('_source').get('request').get('asBase64')
			resAsBase64 = res_dict.get('hits').get('hits')[i].get('_source').get('response').get('asBase64')
			req = base64.b64decode(reqAsBase64).decode("utf-8")
			resp = base64.b64decode(resAsBase64).decode("utf-8")
			path = base64.b64decode(reqAsBase64).decode("utf-8").split(" ")[1]
			protocol = res_dict.get('hits').get('hits')[i].get('_source').get('protocol')
			reqRes = requestResponse(str(host),port,str(protocol),req,resp)
			unit.append(i+1)
			unit.append(method)
			unit.append(host)
			unit.append(types)
			unit.append(path)
			unit.append(status_code)
			unit.append(reqAsBase64)
			unit.append(resAsBase64)
			self._searchTable.add(reqRes)
			data.append(unit)
		return data
	except Exception as e:
		print(e)
		raise Exception(e)