# Burp JVM Property Editor
![](extender-snapshot.png?raw=true)

Small Burp Suite (Free or Professional) Extension to allow the user to view, add, modify, delete or copy the value of [JVM System Properties](https://docs.oracle.com/javase/tutorial/essential/environment/sysprop.html) during Burp usage. May be helpful to some for the purpose of viewing preset property values or setting options for other extensions during runtime rather than on the command line.

# Usage
1. Load the Burp-JVM-Property-Editor-all-[VERSION].jar file in the Burp Suite "Extender" tab, or install through the BApp Store.
2. Navigate to the new "JVM Property Editor" tab and view the table of currently-accessible JVM Property Values.

* The table is populated when the extension is loaded, and is NOT updated in real time. Press the "Refresh Properties" button to re-populate the table with all the current property names and values (this is recommended before attempting to add/remove/edit properties).
* To add a new property:
  1. Press the "Add Property" button and a blank row will be added and automatically selected at the end of the table.
  2. Double click the blank cell in the "Property Name" column and type the name of the property to be created, then press enter.
  3. If the property name is unique and the current installed SecurityManager allows the user to add properties, the new property will be added to the JVM with an empty string value. Otherwise an error message will be printed below the "Add Property" button.
* To modify an existing property:
  1. Double click the cell in the "Property Value" column and type the new value for the property.
  2. To commit the changed value to the JVM press enter. To cancel, press esc.
  3. If the current installed SecurityManager allows the user to edit the selected property, the property value will be changed. Otherwise an error message will be printed below the "Add Property" button.
* To remove an existing property (or properties):
  1. Select the property (or properties) that will be deleted and press the "Delete Selected Property" button.
  2. A confirm prompt will appear (for each selected property): select "Yes" to delete the property and "No" to cancel.
  3. If "Yes" was clicked and the current installed SecurityManager allows the user to remove the selected property, the property value will be changed. Otherwise an error message will be printed below the "Add Property" button.
* To copy the value of an existing property, select the property from the list and click "Copy Selected Property Value". The value of the property will be copied to the clipboard and a message will be printed below the "Add Property" button confirming this.

# Building
Requires Java Development Kit 8 or higher, and Gradle 4 or higher.

1. Clone the Burp-JVM-Property-Editor repository.
2. Open a terminal and navigate to the Burp-JVM-Property-Editor directory.
3. Issue the following command to compile the extension and create the extension jar file (named Burp-JVM-Property-Editor-all-[VERSION].jar): ```gradle fatJar```

# Copyright
Copyright (C) 2016, 2019 Jeffrey Cap (Bort_Millipede)

