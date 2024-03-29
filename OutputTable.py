from javax.swing import JTable
from javax.swing.table import DefaultTableModel
from java.awt.event import MouseListener

# from javax.swing.table import AbstractTableModel
import base64

class IssueTableModel(DefaultTableModel):
	def __init__(self, data, headings):
		# call the DefaultTableModel constructor to populate the table
		DefaultTableModel.__init__(self, data, headings)

	def isCellEditable(self, row, column):
		"""Returns True if cells are editable."""
		canEdit = [False, False, False, False, False, False, False]
		return canEdit[column]

	def getColumnClass(self, column):
		"""Returns the column data class. Optional in this case."""
		from java.lang import Integer, String, Object
		# return Object if you don't know the type.
		columnClasses = [Integer, String, String, String, String, String, String]
		return columnClasses[column]


class IssueTableMouseListener(MouseListener):
	def __init__(self, AS_requestViewer, AS_responseViewer):
		self.AS_requestViewer = AS_requestViewer
		self.AS_responseViewer = AS_responseViewer

	def getClickedIndex(self, event):
		"""Returns the value of the first column of the table row that was
		clicked. This is not the same as the row index because the table
		can be sorted."""
		# get the event source, the table in this case.
		tbl = event.getSource()
		# get the clicked row
		row = tbl.getSelectedRow()
		# get the first value of clicked row
		return tbl.getValueAt(row, 0)
		# return event.getSource.getValueAt(event.getSource().getSelectedRow(), 0)

	def getClickedRow(self, event):
		"""Returns the complete clicked row."""
		tbl = event.getSource()
		return tbl.getModel().getDataVector().elementAt(tbl.convertRowIndexToModel(tbl.getSelectedRow()))

	def mousePressed(self, event):
		pass

	def mouseReleased(self, event):
		pass

	def mouseClicked(self, event):
		if event.getClickCount() == 1:
			rowData = self.getClickedRow(event)
			reqb64 = base64.b64decode(rowData[6])
			resb64 = base64.b64decode(rowData[7])
			self.AS_requestViewer.setMessage(reqb64, True)
			self.AS_responseViewer.setMessage(resb64, False)

	def mouseEntered(self, event):
		pass

	def mouseExited(self, event):
		pass


class IssueTable(JTable):
	"""Issue table."""

	def __init__(self, data, headers, extender):
		self._extender = extender
		self.AS_requestViewer=extender.AS_requestViewer
		self.AS_responseViewer=extender.AS_responseViewer
		# set the table model
		model = IssueTableModel(data, headers)
		self.setModel(model)
		self.setAutoCreateRowSorter(True)
		#self.getSelectionModel().addListSelectionListener(self.nothing)
		# disable the reordering of columns
		self.getTableHeader().setReorderingAllowed(False)
		# assign panel to a field
		self.addMouseListener(IssueTableMouseListener(extender.AS_requestViewer, extender.AS_responseViewer))
		
	def changeSelection(self, row, col, toggle, extend):
		log = self._extender._searchTable.get(row)
		self._extender.AS_requestViewer.setMessage(log.getRequest(),False)
		self._extender.AS_responseViewer.setMessage(log.getResponse(),False)
		self._extender._currentDisplay = log
		JTable.changeSelection(self, row, col, toggle, extend)
	# def nothing(self,event):
	# 	rowData =self.getModel().getDataVector().elementAt(self.convertRowIndexToModel(self.getSelectedRow()))
		
	# 	reqb64 = base64.b64decode(rowData[5])
	#  	resb64 = base64.b64decode(rowData[6])
	# 	self.AS_requestViewer.setMessage(reqb64, True)
	# 	self.AS_responseViewer.setMessage(resb64, False)


class IssueGenWordListModel(DefaultTableModel):
	def __init__(self, data, headings):
		# call the DefaultTableModel constructor to populate the table
		DefaultTableModel.__init__(self, data, headings)

	def isCellEditable(self, row, column):
		"""Returns True if cells are editable."""
		canEdit = [False, False]
		return canEdit[column]

	def getColumnClass(self, column):
		"""Returns the column data class. Optional in this case."""
		from java.lang import Integer, String, Object
		# return Object if you don't know the type.
		columnClasses = [Integer, String]
		return columnClasses[column]
	
class IssueGenWordListTable(JTable):
	def __init__(self, data, headings,extender):
		self._extender=extender
		self.data = data
		self.headings = headings
		model = IssueGenWordListModel(data, headings)
		self.setModel(model)
		self.setAutoCreateRowSorter(True)
		self.getTableHeader().setReorderingAllowed(False)

	
