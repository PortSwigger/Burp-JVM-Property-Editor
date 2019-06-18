/*
	BurpExtender.java
	
	v0.3 (5/19/2019)
	
	Small Burp Suite (Free or Professional) Extension to allow the user to view/add/modify/delete JVM System Properties during Burp usage. May be helpful to some 
	for the purpose of viewing preset property values or setting options for other extensions during runtime rather than on the command line.
*/

package burp;

import java.util.Properties;
import java.util.Set;
import java.util.Arrays;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JPanel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JOptionPane;
import javax.swing.event.TableModelListener;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;

public class BurpExtender implements IBurpExtender,ITab {
	private IBurpExtenderCallbacks callbacks;
	private String title;
	private JPanel component;
	private JTable table;
	private DefaultTableModel dtm;
	private JLabel statusBar;
	
	private static final String version = "v0.3";
	
	public void registerExtenderCallbacks(IBurpExtenderCallbacks cb) {
		callbacks = cb;
		title = "JVM Property Editor";
		callbacks.setExtensionName(title+" "+version);
		
		component = new JPanel();
		
		JPanel buttonPanel = new JPanel(new GridLayout(6,1));
		JButton refButton = new JButton("Refresh Properties");
		JButton delButton = new JButton("Delete Selected Property");
		JButton copyNameButton = new JButton("Copy Selected Property Name");
		JButton copyValueButton = new JButton("Copy Selected Property Value");
		JButton addButton = new JButton("Add Property");
		statusBar = new JLabel("");
		ActionListener buttonAL = new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				JButton b = (JButton) ae.getSource();
				switch(b.getText()) {
					case "Delete Selected Property":
						int[] selected = table.getSelectedRows();
						for(int i=selected.length-1;i>-1;i--) {
							String val = (String) table.getValueAt(selected[i],0);
							boolean remove = false;
							if(val.isEmpty()) {
								remove = true;
							} else {
								int choice = JOptionPane.showConfirmDialog(null,"Are you sure you want to delete JVM Property "+val+"?","Confirm Property Deletion",JOptionPane.YES_NO_OPTION,JOptionPane.WARNING_MESSAGE);
								if(choice==JOptionPane.YES_OPTION) {
									try {
										System.clearProperty(val);
										callbacks.printOutput("Property "+val+" removed.");
										statusBar.setText("<html><font color='orange'>Property "+val+" removed.</font></html>");
										remove = true;
									} catch(SecurityException se) {
										callbacks.printError("Removing Property "+val+" halted by SecurityManager!");
										statusBar.setText("<html><font color='orange'>Removing Property "+val+" halted by SecurityManager!</font></html>");
									}
								}
							}
							if(remove) {
								for(int j=0;j<dtm.getRowCount();j++) {
									String dtmVal = (String) dtm.getValueAt(j,0);
									if(dtmVal.equals(val)) {
										dtm.removeRow(j);
										break;
									}
								}
							}
						}
						break;
					case "Copy Selected Property Name":
						if(table.getSelectedRowCount() == 1) {
							String name = (String) table.getValueAt(table.getSelectedRow(),0);
							if(!name.isEmpty()) {
								Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
								StringSelection ss = new StringSelection(name);
								cb.setContents(ss,ss);
								callbacks.printOutput("Property "+name+" name copied to clipboard.");
								statusBar.setText("<html><font color='orange'>Property "+name+" name copied to clipboard.</font></html>");
							}
						} else {
							callbacks.printOutput("Select only one row to copy property name to clipboard!");
							statusBar.setText("<html><font color='orange'>Select only one row to copy property name to clipboard!</font></html>");
						}
						break;
					case "Copy Selected Property Value":
						if(table.getSelectedRowCount() == 1) {
							String name = (String) table.getValueAt(table.getSelectedRow(),0);
							String val = (String) table.getValueAt(table.getSelectedRow(),1);
							if(!val.isEmpty()) {
								Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
								StringSelection ss = new StringSelection(val);
								cb.setContents(ss,ss);
								callbacks.printOutput("Property "+name+" value copied to clipboard.");
								statusBar.setText("<html><font color='orange'>Property "+name+" value copied to clipboard.</font></html>");
							} else {
								callbacks.printOutput("Property "+name+" value is empty!");
								statusBar.setText("<html><font color='orange'>Property "+name+" value is empty!</font></html>");
							}
						} else {
							callbacks.printOutput("Select only one row to copy property value to clipboard!");
							statusBar.setText("<html><font color='orange'>Select only one row to copy property value to clipboard!</font></html>");
						}
						break;
					case "Add Property":
						statusBar.setText("");
						int rowIndex = dtm.getRowCount()-1;
						if(rowIndex<0) {
							dtm.addRow(new Object[] {"",""});
							table.setRowSelectionInterval(0,0);
							table.scrollRectToVisible(table.getCellRect(0,0,false));
						} else {
							String val = (String) dtm.getValueAt(rowIndex,0);
							if(!val.isEmpty()) dtm.addRow(new Object[] {"",""});
							for(int i=0;i<table.getRowCount();i++) {
								val = (String) table.getValueAt(i,0);
								if(val.isEmpty()) {
									table.setRowSelectionInterval(i,i);
									table.scrollRectToVisible(table.getCellRect(i,0,false));
									break;
								}
							}
						}
						break;
					case "Refresh Properties":
						populateTable();
						statusBar.setText("");
						break;
				}
			}
		};
		refButton.addActionListener(buttonAL);
		delButton.addActionListener(buttonAL);
		copyNameButton.addActionListener(buttonAL);
		copyValueButton.addActionListener(buttonAL);
		addButton.addActionListener(buttonAL);
		buttonPanel.add(refButton);
		buttonPanel.add(delButton);
		buttonPanel.add(copyNameButton);
		buttonPanel.add(copyValueButton);
		buttonPanel.add(addButton);
		buttonPanel.add(statusBar);
		
		dtm = new DefaultTableModel(0,2) {
			public String getColumnName(int column) {
				switch(column) {
					case 0: return "Property Name";
					case 1: return "Property Value";
					default: return "";
				}
			}
			public boolean isCellEditable(int row,int column) {
				if(column==1) {
					return true;
				} else if(getValueAt(row,column).toString().isEmpty()) {
					return true;
				}
				return false;
			}
			public Class<?> getColumnClass(int columnIndex) {
				return String.class;
			}
		};
		dtm.addTableModelListener(new TableModelListener() {
			public void tableChanged(TableModelEvent tme) {
				switch(tme.getType()) {
					case TableModelEvent.UPDATE:
						int firstRow = tme.getFirstRow();
						int lastRow = tme.getLastRow();
						if(firstRow==lastRow) {
							String propName = (String) dtm.getValueAt(lastRow,0);
							if(tme.getColumn()==0) {
								if(System.getProperty(propName)!=null) {
									statusBar.setText("<html><font color='orange'>Property "+propName+" already exists!</font></html>");
									callbacks.printOutput("Property "+propName+" already exists!");
									dtm.removeRow(lastRow);
									for(int i=0;i<dtm.getRowCount();i++) {
										String n = (String) dtm.getValueAt(i,0);
										if(n.equals(propName)) {
											table.setRowSelectionInterval(i,i);
											table.scrollRectToVisible(table.getCellRect(i,1,false));
											break;
										}
									}
								} else {
									boolean found=false;
									for(int i=0;i<dtm.getRowCount();i++) {
										String val = (String) dtm.getValueAt(i,0);
										if(val.equals(propName)) {
											found = true;
											dtm.setValueAt((String) "",i,1);
											break;
										} 
									}
									System.setProperty(propName,"");
									if(found) {
										for(int i=0;i<table.getRowCount();i++) {
											String val = (String) table.getValueAt(i,0);
											if(propName.equals(val)) {
												table.setRowSelectionInterval(i,i);
												table.scrollRectToVisible(table.getCellRect(i,1,false));
												break;
											}
										}
									}
									callbacks.printOutput("Property "+propName+" added.");
									statusBar.setText("<html><font color='orange'>Property "+propName+" added.</font></html>");
								}
							} else {
								String propValue = (String) dtm.getValueAt(lastRow,1);
								String origValue = System.getProperty(propName);
								if(!propValue.equals(origValue)) {
									try {
										System.setProperty(propName,propValue);
										dtm.setValueAt(System.getProperty(propName),lastRow,1);
										callbacks.printOutput("Property "+propName+" value "+(origValue!=null ? "changed from \'"+origValue+"\' " : "set ")+"to \'"+propValue+"\'.");
										statusBar.setText("<html><font color='orange'>Property "+propName+" value "+(origValue!=null ? "changed from \'"+origValue+"\' " : "set ")+"to \'"+propValue+"\'.</font></html>");
									} catch(SecurityException se) {
										dtm.setValueAt(origValue,lastRow,1);
										callbacks.printError("Changing value for Property "+propName+" halted by SecurityManager!");
										statusBar.setText("<html><font color='orange'>Changing value for Property "+propName+" halted by SecurityManager!</font></html>");
									}
								}
							}
						}
						break;
				}
			}
		});
		table = new JTable(dtm);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		table.setAutoCreateRowSorter(true);
		table.getColumn(table.getColumnName(0)).setPreferredWidth(200);
		table.getColumn(table.getColumnName(1)).setPreferredWidth(230);
		JScrollPane scroll = new JScrollPane(table);
		
		populateTable();
		
		component.add(buttonPanel);
		component.add(scroll);
		callbacks.addSuiteTab(this);
	}
	
	public String getTabCaption() {
		return title;
	}
	
	public Component getUiComponent() {
		JScrollPane jsp = new JScrollPane(component);
		callbacks.customizeUiComponent(jsp);
		return jsp;
	}
	
	private void populateTable() {
		dtm.setRowCount(0);
		Properties props = System.getProperties();
		Set<String> propNameSet = props.stringPropertyNames();
		String[] propNames = propNameSet.toArray(new String[] {});
		Arrays.sort(propNames);
		for(int i=0;i<propNames.length;i++) {
			dtm.addRow(new Object[] {propNames[i],props.get(propNames[i])});
		}
	}
}
