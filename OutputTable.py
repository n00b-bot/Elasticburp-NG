from javax.swing import JTable
from javax.swing.table import DefaultTableModel
from java.awt.event import MouseListener


class IssueTableModel(DefaultTableModel):
	def __init__(self, data, headings):
		# call the DefaultTableModel constructor to populate the table
		DefaultTableModel.__init__(self, data, headings)

	def isCellEditable(self, row, column):
		"""Returns True if cells are editable."""
		# make all rows and columns uneditable.
		# do we need to check the column value here?
		canEdit = [False, False, False, False, False]
		return canEdit[column]
		# return False

	def getColumnClass(self, column):
		"""Returns the column data class. Optional in this case."""
		from java.lang import Integer, String, Object
		# return Object if you don't know the type.
		# only works if we are not changing the number of columns
		columnClasses = [Integer, String, String, String, String]
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
		# print "mouse pressed", event.getClickCount()
		pass

	def mouseReleased(self, event):
		# print "mouse released", event.getClickCount()
		pass

	# event.getClickCount() returns the number of clicks.
	def mouseClicked(self, event):
		if event.getClickCount() == 1:
			rowData = self.getClickedRow(event)
			self.AS_requestViewer.setMessage("Test", True)

	def mouseEntered(self, event):
		pass

	def mouseExited(self, event):
		pass


class IssueTable(JTable):
	"""Issue table."""

	def __init__(self, data, headers, AS_requestViewer, AS_responseViewer):

		# set the table model
		model = IssueTableModel(data, headers)
		self.setModel(model)
		self.setAutoCreateRowSorter(True)
		# disable the reordering of columns
		self.getTableHeader().setReorderingAllowed(False)
		# assign panel to a field
		self.addMouseListener(IssueTableMouseListener(AS_requestViewer, AS_responseViewer))
