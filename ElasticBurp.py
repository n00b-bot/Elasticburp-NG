# ElasticBurp
# Copyright 2016 Thomas Patzke <thomas@patzke.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
 
from burp import IBurpExtender, IBurpExtenderCallbacks, IHttpListener, IRequestInfo, IParameter, IContextMenuFactory, ITab, IMessageEditorController
from javax.swing import JMenuItem, ProgressMonitor, JPanel, BoxLayout, JLabel, JTextField, JCheckBox, JButton, Box, JOptionPane, JTextArea, JScrollPane, JTable, JPopupMenu, JTabbedPane, JSplitPane, JFrame, table
from javax.swing.table import DefaultTableModel
from java.awt import Dimension, Color,BorderLayout
from java.awt.event import MouseListener
from elasticsearch_dsl.connections import connections
from elasticsearch_dsl import Index
from elasticsearch.helpers import bulk
from java.util import ArrayList
from doc_HttpRequestResponse import DocHTTPRequestResponse
from datetime import datetime
from email.utils import parsedate_tz, mktime_tz
from tzlocal import get_localzone
import hashlib
import re
import redis
import traceback
from redis import connection
import errno
import socket
import threading
import base64
import getRequestFromHash
import SearchBuilder
import sys
import array
from OutputTable import *
import json
import os
import re
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection

reload(sys)  
sys.setdefaultencoding('utf-8')
sys.setrecursionlimit(200)
try:
	tz = get_localzone()
except:
	tz = None
reDateHeader = re.compile("^Date:\s*(.*)$", flags=re.IGNORECASE)

ES_host = "localhost"
ES_index = "wase-thread"
Burp_Tools = IBurpExtenderCallbacks.TOOL_PROXY
Burp_onlyResponses = True       # Usually what you want, responses also contain requests
#########################################

def genListVuln():
		path_to_json = './GfPatterns'
		json_files = [pos_json for pos_json in os.listdir(path_to_json) if pos_json.endswith('.json')]
		json_list=[]
		for file in json_files:
			file="./GfPatterns/"+file
			with open(file,'r') as f:
				contents = json.loads(f.read())
				json_list.append(contents)
		types_vul=[]
		types_of_patterns=[]
		for pattern_vul in json_list:
			types_vul.append(pattern_vul['flags'])
			types_of_patterns.append(pattern_vul['patterns'])
		# print(types_vul)
		# print(types_of_patterns)
		return types_vul,types_of_patterns

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, IMessageEditorController, ITab):

	def registerExtenderCallbacks(self, callbacks):
		self.types_vul,self.types_of_patterns = genListVuln()
		self.callbacks = callbacks
		self.helpers = callbacks.getHelpers()
		callbacks.setExtensionName("Storing HTTP Requests/Responses into ElasticSearch")
		self.callbacks.registerHttpListener(self)
		self.callbacks.registerContextMenuFactory(self)
		self.out = callbacks.getStdout()
		self.lastTimestamp = None
		self.confESHost = self.callbacks.loadExtensionSetting("elasticburp.host") or ES_host
		self.confESIndex = self.callbacks.loadExtensionSetting("elasticburp.index") or ES_index
		self.confBurpTools = int(self.callbacks.loadExtensionSetting("elasticburp.tools") or Burp_Tools)
		self.confRedis = False
		self.AS_requestViewer = self.callbacks.createMessageEditor(self, False)
		self.AS_responseViewer = self.callbacks.createMessageEditor(self, False)
		saved_onlyresp = self.callbacks.loadExtensionSetting("elasticburp.onlyresp") 
		if saved_onlyresp == "True":
			self.confBurpOnlyResp = True
		elif saved_onlyresp == "False":
			self.confBurpOnlyResp = False
		else:
			self.confBurpOnlyResp = bool(int(saved_onlyresp or Burp_onlyResponses))
		self._searchTable = ArrayList()
		self.callbacks.addSuiteTab(self)
		self.applyConfig()

	def getHttpService(self):
		return self._currentDisplay.getHttpService()
	def getRequest(self):
		return self._currentDisplay.getRequest()
	def getResponse(self):
		return self._currentDisplay.getResponse()
	
	def applyConfig(self):
		try:
			print("Connecting to '%s', index '%s'" % (self.confESHost, self.confESIndex))
			self.es = connections.create_connection(hosts=[self.confESHost],timeout=20)
			self.idx = Index(self.confESIndex)
			self.idx.document(DocHTTPRequestResponse)
			if self.confRedis:
				connection.NONBLOCKING_EXCEPTION_ERROR_NUMBERS[socket.error] = errno.EAGAIN
				connection.NONBLOCKING_EXCEPTIONS = tuple(connection.NONBLOCKING_EXCEPTION_ERROR_NUMBERS.keys())
				self.redis = redis.Redis(host='localhost', port=6379, db=0)
				print(self.redis.ping())
				print("redis is config")
			if self.idx.exists():
				self.idx.open()
				print("idx exists")
			else:
				self.idx.create()
				print("id create")
			self.callbacks.saveExtensionSetting("elasticburp.host", self.confESHost)
			self.callbacks.saveExtensionSetting("elasticburp.index", self.confESIndex)
			self.callbacks.saveExtensionSetting("elasticburp.tools", str(self.confBurpTools))
			self.callbacks.saveExtensionSetting("elasticburp.onlyresp", str(int(self.confBurpOnlyResp)))
		except Exception as e:
			JOptionPane.showMessageDialog(self.panelBasic, "<html><p style='width: 300px'>Error while initializing ElasticSearch: %s</p></html>" % (str(e)), "Error", JOptionPane.ERROR_MESSAGE)
	
	def hashGetConfig(self):
		hash = self.uiHashVal.getText()
		hash.strip()
		esServer = "http://" + self.confESHost + ":9200"
		esIndex = self.confESIndex
		result = getRequestFromHash.getReqFromHash(esServer, esIndex, hash)
		try:        
			if result.req == "empty":
				self.uiOutReq.setText("Not found")
			else:
				if len(result.pro) == 0 and len(result.host) ==  0:
					self.uiOutReq.setText("Error on finding request")
				else:
					self.reqHost = result.host[0]
					self.proto = result.pro[0]
					self.reqPort = result.port[0]
					self.uiOutReq.setText(result.req)
		except:
			self.uiOutReq.setText("Can't find " + hash)

	def sendRequestRepeaterConfig(self):
		reqtext = self.uiOutReq.getText()
		host = self.reqHost
		port = int(self.reqPort)
		proto  = str(self.proto)
		secure = True if proto == "https" else False
		req = array.array("b",str(reqtext))
		self.callbacks.sendToRepeater(host, port, secure, req, "ElasticBurp-NG")

	def queryASConfig(self):
		tableModel = self.uiASOutputTbl.getModel()
		query = self.uiASValue.getText()
		query.strip()
		esServer = "http://" + self.confESHost + ":9200"
		esIndex = self.confESIndex
		kibanaServer = "http://" + self.confESHost + ":5601"
		try:
			result = SearchBuilder.getReqFromAS(self,kibanaServer,esServer, esIndex, query)
			for i in range(0,len(result)):
				tableModel.addRow(result[i])
		except Exception as e:
			JOptionPane.showMessageDialog(self.panelBasic, "<html><p style='width: 300px'>%s</p></html>" % (str(e)), "Error", JOptionPane.ERROR_MESSAGE)

	### ITab ###
	def getTabCaption(self):
		return "ElasticBurp-NG"

	def applyConfigUI(self, event):
		#self.idx.close()
		self.confESHost = self.uiESHost.getText()
		self.confESIndex = self.uiESIndex.getText()
		self.confBurpTools = int((self.uiCBSuite.isSelected() and IBurpExtenderCallbacks.TOOL_SUITE) | (self.uiCBTarget.isSelected() and IBurpExtenderCallbacks.TOOL_TARGET) | (self.uiCBProxy.isSelected() and IBurpExtenderCallbacks.TOOL_PROXY) | (self.uiCBSpider.isSelected() and IBurpExtenderCallbacks.TOOL_SPIDER) | (self.uiCBScanner.isSelected() and IBurpExtenderCallbacks.TOOL_SCANNER) | (self.uiCBIntruder.isSelected() and IBurpExtenderCallbacks.TOOL_INTRUDER) | (self.uiCBRepeater.isSelected() and IBurpExtenderCallbacks.TOOL_REPEATER) | (self.uiCBSequencer.isSelected() and IBurpExtenderCallbacks.TOOL_SEQUENCER) | (self.uiCBExtender.isSelected() and IBurpExtenderCallbacks.TOOL_EXTENDER))
		self.confBurpOnlyResp = self.uiCBOptRespOnly.isSelected()
		self.confRedis= self.uiRedis.isSelected()
		self.applyConfig()

	def resetConfigUI(self, event):
		self.uiESHost.setText(self.confESHost)
		self.uiESIndex.setText(self.confESIndex)
		self.uiCBSuite.setSelected(bool(self.confBurpTools & IBurpExtenderCallbacks.TOOL_SUITE))
		self.uiCBTarget.setSelected(bool(self.confBurpTools & IBurpExtenderCallbacks.TOOL_TARGET))
		self.uiCBProxy.setSelected(bool(self.confBurpTools & IBurpExtenderCallbacks.TOOL_PROXY))
		self.uiCBSpider.setSelected(bool(self.confBurpTools & IBurpExtenderCallbacks.TOOL_SPIDER))
		self.uiCBScanner.setSelected(bool(self.confBurpTools & IBurpExtenderCallbacks.TOOL_SCANNER))
		self.uiCBIntruder.setSelected(bool(self.confBurpTools & IBurpExtenderCallbacks.TOOL_INTRUDER))
		self.uiCBRepeater.setSelected(bool(self.confBurpTools & IBurpExtenderCallbacks.TOOL_REPEATER))
		self.uiCBSequencer.setSelected(bool(self.confBurpTools & IBurpExtenderCallbacks.TOOL_SEQUENCER))
		self.uiCBExtender.setSelected(bool(self.confBurpTools & IBurpExtenderCallbacks.TOOL_EXTENDER))
		self.uiCBOptRespOnly.setSelected(self.confBurpOnlyResp)

	def hashGetConfigUI(self, event):
		self.hashGetConfig()

	def sendRequestRepeaterConfigUI(self, event):
		self.sendRequestRepeaterConfig()

	def queryASConfigUI(self, event):
		tableModel = self.uiASOutputTbl.getModel()
		while tableModel.getRowCount() > 0:
			tableModel.removeRow(0)
		self.queryASConfig()


	def copy_selected_row(self,table):
		column_index = 1  # index of the column you want to get data from
		table_model = table.getModel()
		column_data = []
		clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
		for row_index in range(table_model.getRowCount()):
			select_data = table_model.getValueAt(row_index, column_index)
			column_data.append(select_data)
		print(column_data)
		clipboard.setContents(StringSelection(''.join(column_data)), None)


	def queryGetWordlist(self,event):
		if (os.system("py ./genDIR.py")==0):
			pass
		else:
			os.system("python3 ./genDIR.py")
		data=[]
		count=1
		with open("./DIR.txt",'r') as f:
			for line in f:
				temp=[count,line]
				data.append(temp)
				count+=1
		f.close()
		
		columns = ['#', 'Path']

		frame = JFrame('WordList')
		table = JTable(data, columns)
		table.getColumnModel().getColumn(0).setPreferredWidth(20)
		scrollPane = JScrollPane(table)
		button_copy = JButton('Copy')
		button_copy.addActionListener(
			lambda event: self.copy_selected_row(table)
		)

		panel_buttons = JPanel()
		panel_buttons.add(button_copy)

		frame.add(scrollPane)
		frame.add(panel_buttons, BorderLayout.PAGE_END)
		frame.setSize(800, 700)
		frame.setLocationRelativeTo(None)
		frame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE)
		frame.setVisible(True)


	def getUiComponent(self):
		self.panelBasic = JPanel()
		self.panelAvSearch = JPanel()
		self.panelGenWordList = JPanel()
		self.tabIssue = JTabbedPane()

		#---------------------Push and Get Feature----------------------------
		
		self.panelBasic.setLayout(BoxLayout(self.panelBasic, BoxLayout.PAGE_AXIS))

		self.uiESHostLine = JPanel()
		self.uiESHostLine.setLayout(BoxLayout(self.uiESHostLine, BoxLayout.LINE_AXIS))
		self.uiESHostLine.setAlignmentX(JPanel.LEFT_ALIGNMENT)
		self.uiESHostLine.add(JLabel("ElasticSearch Host: "))
		self.uiESHost = JTextField(40)
		self.uiESHost.setMaximumSize(self.uiESHost.getPreferredSize())
		self.uiESHostLine.add(self.uiESHost)
		self.panelBasic.add(self.uiESHostLine)

		self.uiESIndexLine = JPanel()
		self.uiESIndexLine.setLayout(BoxLayout(self.uiESIndexLine, BoxLayout.LINE_AXIS))
		self.uiESIndexLine.setAlignmentX(JPanel.LEFT_ALIGNMENT)
		self.uiESIndexLine.add(JLabel("ElasticSearch Index: "))
		self.uiESIndex = JTextField(40)
		self.uiESIndex.setMaximumSize(self.uiESIndex.getPreferredSize())
		self.uiESIndexLine.add(self.uiESIndex)
		self.panelBasic.add(self.uiESIndexLine)

		uiToolsLine = JPanel()
		uiToolsLine.setLayout(BoxLayout(uiToolsLine, BoxLayout.LINE_AXIS))
		uiToolsLine.setAlignmentX(JPanel.LEFT_ALIGNMENT)
		self.uiCBSuite = JCheckBox("Suite")
		uiToolsLine.add(self.uiCBSuite)
		uiToolsLine.add(Box.createRigidArea(Dimension(10, 0)))
		self.uiCBTarget = JCheckBox("Target")
		uiToolsLine.add(self.uiCBTarget)
		uiToolsLine.add(Box.createRigidArea(Dimension(10, 0)))
		self.uiCBProxy = JCheckBox("Proxy")
		uiToolsLine.add(self.uiCBProxy)
		uiToolsLine.add(Box.createRigidArea(Dimension(10, 0)))
		self.uiCBSpider = JCheckBox("Spider")
		uiToolsLine.add(self.uiCBSpider)
		uiToolsLine.add(Box.createRigidArea(Dimension(10, 0)))
		self.uiCBScanner = JCheckBox("Scanner")
		uiToolsLine.add(self.uiCBScanner)
		uiToolsLine.add(Box.createRigidArea(Dimension(10, 0)))
		self.uiCBIntruder = JCheckBox("Intruder")
		uiToolsLine.add(self.uiCBIntruder)
		uiToolsLine.add(Box.createRigidArea(Dimension(10, 0)))
		self.uiCBRepeater = JCheckBox("Repeater")
		uiToolsLine.add(self.uiCBRepeater)
		uiToolsLine.add(Box.createRigidArea(Dimension(10, 0)))
		self.uiCBSequencer = JCheckBox("Sequencer")
		uiToolsLine.add(self.uiCBSequencer)
		uiToolsLine.add(Box.createRigidArea(Dimension(10, 0)))
		self.uiCBExtender = JCheckBox("Extender")
		uiToolsLine.add(self.uiCBExtender)
		uiToolsLine.add(Box.createRigidArea(Dimension(10, 0)))
		self.uiRedis = JCheckBox("Redis Cache")
		self.uiRedis.setSelected(True)
		uiToolsLine.add(self.uiRedis)
		self.panelBasic.add(uiToolsLine)
		self.panelBasic.add(Box.createRigidArea(Dimension(0, 10)))

		uiOptionsLine = JPanel()
		uiOptionsLine.setLayout(BoxLayout(uiOptionsLine, BoxLayout.LINE_AXIS))
		uiOptionsLine.setAlignmentX(JPanel.LEFT_ALIGNMENT)
		self.uiCBOptRespOnly = JCheckBox("Process only responses (include requests)")
		uiOptionsLine.add(self.uiCBOptRespOnly)
		self.panelBasic.add(uiOptionsLine)
		self.panelBasic.add(Box.createRigidArea(Dimension(0, 10)))

		uiButtonsLine = JPanel()
		uiButtonsLine.setLayout(BoxLayout(uiButtonsLine, BoxLayout.LINE_AXIS))
		uiButtonsLine.setAlignmentX(JPanel.LEFT_ALIGNMENT)
		uiButtonsLine.add(JButton("Apply", actionPerformed=self.applyConfigUI))
		uiButtonsLine.add(JButton("Reset", actionPerformed=self.resetConfigUI))
		self.panelBasic.add(uiButtonsLine)
		self.resetConfigUI(None)

		#-----------Generate Request from Hash Function GUI--------------------

		self.uiLogLine = JPanel()
		self.uiLogLine.setLayout(BoxLayout(self.uiLogLine, BoxLayout.LINE_AXIS))
		self.uiLogLine.setAlignmentX(JPanel.LEFT_ALIGNMENT)
		self.uiLogLine.add(JLabel("Gen request from Hash"))
		self.panelBasic.add(self.uiLogLine)

		self.uiHashGen = JPanel()
		self.uiHashGen.setLayout(BoxLayout(self.uiHashGen, BoxLayout.LINE_AXIS))
		self.uiHashGen.setAlignmentX(JPanel.LEFT_ALIGNMENT)
		self.uiHashVal = JTextField(40)
		self.uiHashVal.setMaximumSize(self.uiHashVal.getPreferredSize())
		self.uiHashGen.add(self.uiHashVal)
		self.uiHashGen.add(JButton("Get", actionPerformed=self.hashGetConfigUI))
		self.uiHashGen.add(JButton("Send to Repeater", actionPerformed=self.sendRequestRepeaterConfigUI))
		self.panelBasic.add(self.uiHashGen)


		self.uiOutLine = JPanel()
		self.uiOutLine.setLayout(BoxLayout(self.uiOutLine, BoxLayout.LINE_AXIS))
		self.uiOutLine.setAlignmentX(JPanel.LEFT_ALIGNMENT)
		self.uiOutReqSP = JScrollPane()
		self.uiOutReq = JTextArea()
		menu=JPopupMenu("Popup")
		menu.add(JMenuItem("Send To Repeater",actionPerformed=self.sendRequestRepeaterConfigUI))
		self.uiOutReq.componentPopupMenu=menu
		self.uiOutReq.setLineWrap(True)
		self.uiOutReq.setWrapStyleWord(True)
		self.uiOutReq.editable = False
		self.uiOutReqSP.setViewportView(self.uiOutReq)
		self.uiOutLine.add(self.uiOutReqSP)
		self.panelBasic.add(self.uiOutLine)
		#---------------------------------------------------------------------
		#---------------------------------------------------------------------
		#------------------------Advanced Search Feature----------------------
		table = JSplitPane(JSplitPane.VERTICAL_SPLIT)
		top = JSplitPane(JSplitPane.VERTICAL_SPLIT)
		
		"""Disable Resize"""
		top.setDividerSize(0)

		self.panelAvSearch.setLayout(BoxLayout(self.panelAvSearch, BoxLayout.Y_AXIS))

		self.uiASInput = JPanel()
		self.uiASInput.setLayout(BoxLayout(self.uiASInput, BoxLayout.X_AXIS))
		self.uiASInput.setAlignmentX(JPanel.CENTER_ALIGNMENT)
		self.uiASValue = JTextField(100,actionPerformed=self.queryASConfigUI)
		self.uiASValue.setMaximumSize(self.uiASValue.getPreferredSize())
		self.uiASInput.add(self.uiASValue)
		self.uiASInput.add(JButton("Query", actionPerformed=self.queryASConfigUI))
		self.uiASInput.add(JButton("Gen",actionPerformed=self.queryGetWordlist))
		#self.panelAvSearch.add()
		top.setLeftComponent(self.uiASInput)


		asOutData = [
			[1,"GET", "www.example.com","SQL" ,"/robots.txt", "200", "dGVzdA==", "MTIzMzIx"],
			[2, "GET", "www.example.com","LFI" ,"/lmao", "404", "MTIzMzIx", "dGVzdA=="],
		]
		asOutHead = ["#", "Method", "Host", "Types", "Path", "Code", "Req", "Res"]
		self.uiASOutputTbl = IssueTable(asOutData, asOutHead, self)
		tableWidth = self.uiASOutputTbl.getPreferredSize().width 
		sizeCol0 = int(round(tableWidth / 50 * 1))
		sizeCol1 = int(round(tableWidth / 50 * 5))
		sizeCol2 = int(round(tableWidth / 50 * 8))
		sizeCol3 = int(round(tableWidth / 50 * 10))
		sizeCol4 = int(round(tableWidth / 50 * 25))  
		self.uiASOutputTbl.getColumn("#").setPreferredWidth(sizeCol1)
		self.uiASOutputTbl.getColumn("#").setMaxWidth(sizeCol3)
		self.uiASOutputTbl.getColumn("Method").setMinWidth(sizeCol3)
		self.uiASOutputTbl.getColumn("Method").setMaxWidth(sizeCol3)
		self.uiASOutputTbl.getColumn("Host").setPreferredWidth(sizeCol4)
		self.uiASOutputTbl.getColumn("Types").setPreferredWidth(sizeCol3)
		self.uiASOutputTbl.getColumn("Path").setPreferredWidth(sizeCol4)
		self.uiASOutputTbl.getColumn("Code").setMinWidth(sizeCol2)
		self.uiASOutputTbl.getColumn("Code").setMaxWidth(sizeCol2)
		self.uiASOutputTbl.removeColumn(self.uiASOutputTbl.getColumnModel().getColumn(6))
		self.uiASOutputTbl.removeColumn(self.uiASOutputTbl.getColumnModel().getColumn(6))
		requestTable = JPanel()
		requestTable.setLayout(BoxLayout(requestTable, BoxLayout.LINE_AXIS))
		self.uiASOutputJP = JScrollPane()
		self.uiASOutputJP.setViewportView(self.uiASOutputTbl)
		requestTable.add(self.uiASOutputJP)
		table.setLeftComponent(requestTable)



		requestResponse =JPanel()
		requestResponse.setLayout(BoxLayout(requestResponse, BoxLayout.X_AXIS))
		self._splitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._splitpane.setLeftComponent(self.AS_requestViewer.getComponent())
		self._splitpane.setRightComponent(self.AS_responseViewer.getComponent())
		self._splitpane.setResizeWeight(0.5)
		requestResponse.add(self._splitpane)
		table.setRightComponent(requestResponse)
		top.setRightComponent(table)
		self.panelAvSearch.add(top,BorderLayout.CENTER)


		#---------------------------------------------------------------------
		self.tabIssue.addTab("Push & Get", self.panelBasic)
		self.tabIssue.addTab("Advanced Search", self.panelAvSearch)
		# self.tabIssue.addTab("Gen Wordlist", self.panelGenWordList)
		return self.tabIssue

	def checkHash(self,hashes):
		check = self.redis.get(hashes)
		if check == None:
			self.redis.set(hashes,"1")
			return False
		else:
			return True
		
	def genGetHash(self,msg):
		def menuGetHash(e):
			hash = hashlib.md5(bytearray(msg.getRequest()).decode('utf-8')).hexdigest()
			self.uiHashVal.setText(hash)
		return menuGetHash


	def matches_param(self,param):
			count=0
			index=[]
			for values in self.types_of_patterns:
				for value in values:
					if str(param) == str(value).rstrip("="):
						# print(param+" in "+self.types_vul[count])
						index.append(count)
						break
				count+=1		
			return index	
	### IHttpListener ###
	def processHttpMessage(self, tool, isRequest, msg):
		if not tool & self.confBurpTools or isRequest and self.confBurpOnlyResp:
			return	
		#refactory
		iRequest = self.helpers.analyzeRequest(msg)
		getUrl=iRequest.getUrl().toString()
		parameters = iRequest.getParameters()
		types = []
		pattern = r"\.js|\.gif|\.jpg|\.png|\.css"
		match = re.search(pattern, getUrl)
		if  match==None:
			for parameter in parameters:
					ptype = parameter.getType()
					# print(ptype)
					if ptype != IParameter.PARAM_COOKIE or ptype == None:
						match_types_index=self.matches_param(parameter.getName())
						# print(parameter.getName())
						for i in range(0,len(match_types_index),1):
							index_flags=match_types_index[i]
							if self.types_vul[index_flags] not in types:
								types.append(self.types_vul[index_flags])

			#-------------------------------------------------------
			doc = self.genESDoc(msg)
			doc.request.asBase64= base64.b64encode(bytearray(msg.getRequest()).decode("utf-8"))
			doc.response.asBase64 = base64.b64encode(bytearray(msg.getResponse()).decode("utf-8"))
			doc.types = ','.join(types)
			doc.hashes=hashlib.md5(bytearray(msg.getRequest()).decode('utf-8')).hexdigest()
			t1=threading.Thread(target=doc.save, args=())
			if self.confRedis:
				check=self.checkHash(doc.hashes)
				if not check:
					print(doc.hashes+" is cached")
					t1.start()
				else:
					print("cached :"+doc.hashes)
			else:
				t1.start()


	### IContextMenuFactory ###
	def createMenuItems(self, invocation):
		menuItems = list()
		selectedMsgs = invocation.getSelectedMessages()
		if selectedMsgs != None and len(selectedMsgs) == 1:
			# menuItems.append(JMenuItem("Add to ElasticSearch Index", actionPerformed=self.genAddToES(selectedMsgs, invocation.getInputEvent().getComponent())))
			menuItems.append(JMenuItem("Get Hash", actionPerformed=self.genGetHash(selectedMsgs[0])))
		return menuItems

	def genAddToES(self, msgs, component):
		def menuAddToES(e):
			progress = ProgressMonitor(component, "Feeding ElasticSearch", "", 0, len(msgs))
			i = 0
			docs = list()
			for msg in msgs:
				if not Burp_onlyResponses or msg.getResponse():
					docs.append(self.genESDoc(msg, timeStampFromResponse=True).to_dict(True))
				i += 1
				progress.setProgress(i)
			success, failed = bulk(self.es, docs, True, raise_on_error=False)
			progress.close()
			JOptionPane.showMessageDialog(self.panelBasic, "<html><p style='width: 300px'>Successful imported %d messages, %d messages failed.</p></html>" % (success, failed), "Finished", JOptionPane.INFORMATION_MESSAGE)
		return menuAddToES

	### Interface to ElasticSearch ###
	def genESDoc(self, msg, timeStampFromResponse=False):
		httpService = msg.getHttpService()
		doc = DocHTTPRequestResponse(protocol=httpService.getProtocol(), host=httpService.getHost(), port=httpService.getPort())
		doc.meta.index = self.confESIndex
		# doc.types=""
		request = msg.getRequest()
		response = msg.getResponse()

		if request:
			iRequest = self.helpers.analyzeRequest(msg)
			doc.request.method = iRequest.getMethod()
			doc.request.url = iRequest.getUrl().toString()

			headers = iRequest.getHeaders()
			for header in headers:
				try:
					doc.add_request_header(header)
				except:
					doc.request.requestline = header

			parameters = iRequest.getParameters()
			for parameter in parameters:
				ptype = parameter.getType()
				if ptype == IParameter.PARAM_URL:
					typename = "url"
				elif ptype == IParameter.PARAM_BODY:
					typename = "body"
				elif ptype == IParameter.PARAM_COOKIE:
					typename = "cookie"
				elif ptype == IParameter.PARAM_XML:
					typename = "xml"
				elif ptype == IParameter.PARAM_XML_ATTR:
					typename = "xmlattr"
				elif ptype == IParameter.PARAM_MULTIPART_ATTR:
					typename = "multipartattr"
				elif ptype == IParameter.PARAM_JSON:
					typename = "json"
				else:
					typename = "unknown"
				
				name = parameter.getName()
				value = parameter.getValue()
				doc.add_request_parameter(typename, name, value)

			ctype = iRequest.getContentType()
			if ctype == IRequestInfo.CONTENT_TYPE_NONE:
				doc.request.content_type = "none"
			elif ctype == IRequestInfo.CONTENT_TYPE_URL_ENCODED:
				doc.request.content_type = "urlencoded"
			elif ctype == IRequestInfo.CONTENT_TYPE_MULTIPART:
				doc.request.content_type = "multipart"
			elif ctype == IRequestInfo.CONTENT_TYPE_XML:
				doc.request.content_type = "xml"
			elif ctype == IRequestInfo.CONTENT_TYPE_JSON:
				doc.request.content_type = "json"
			elif ctype == IRequestInfo.CONTENT_TYPE_AMF:
				doc.request.content_type = "amf"
			else:
				doc.request.content_type = "unknown"

			bodyOffset = iRequest.getBodyOffset()
			doc.request.body = request[bodyOffset:].tostring().decode("ascii", "replace")

		if response:
			iResponse = self.helpers.analyzeResponse(response)

			doc.response.status = iResponse.getStatusCode()
			doc.response.content_type = iResponse.getStatedMimeType()
			doc.response.inferred_content_type = iResponse.getInferredMimeType()

			headers = iResponse.getHeaders()
			dateHeader = None
			for header in headers:
				try:
					doc.add_response_header(header)
					match = reDateHeader.match(header)
					if match:
						dateHeader = match.group(1)
				except:
					doc.response.responseline = header

			cookies = iResponse.getCookies()
			for cookie in cookies:
				expCookie = cookie.getExpiration()
				expiration = None
				if expCookie:
					try:
						expiration = str(datetime.fromtimestamp(expCookie.time / 1000))
					except:
						pass
				doc.add_response_cookie(cookie.getName(), cookie.getValue(), cookie.getDomain(), cookie.getPath(), expiration)

			bodyOffset = iResponse.getBodyOffset()
			doc.response.body = response[bodyOffset:].tostring().decode("ascii", "replace")

			if timeStampFromResponse:
				if dateHeader:
					try:
						doc.timestamp = datetime.fromtimestamp(mktime_tz(parsedate_tz(dateHeader)), tz) # try to use date from response header "Date"
						self.lastTimestamp = doc.timestamp
					except:
						doc.timestamp = self.lastTimestamp      # fallback: last stored timestamp. Else: now

		return doc
