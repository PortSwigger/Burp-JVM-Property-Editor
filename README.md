# Burp-JVM-Property-Editor
Small Burp Suite Extension that allows users to view, add, modify or remove JVM System Properties (https://docs.oracle.com/javase/tutorial/essential/environment/sysprop.html) during runtime. May be helpful for the purpose of viewing preset property values or setting options for other extensions during runtime rather than on the command line. Can be used with both the Free and Professional versions of Burp Suite.

# Usage
1. Load the burp-jvm-property-editor-[VERSION].jar file in the Burp Suite "Extensions" tab.
2. Navigate to the new "JVM Property Editor" tab and view the table of currently-accessible JVM Property Values.
  * The table is populated when the extension is loaded and is NOT updated in real time. Press the "Refresh Properties" button to repopulate the table with all the current property keys and values (this is recommended before attempting to add/remove/edit properties).
3. To add a new Property:
  1. Press the "Add Property" button and a blank row will be added and automatically selected at the end of the table.
  2. Double click the blank cell in the "Property Key" column and type the name of the property to be created, then press enter.
  3. If the property name is unique and the current installed SecurityManager allows the user to add properties, the new property will be added to the JVM with an empty string value. Otherwise an error message will be printed below the "Add Property" button.
4. To modify an existing property:
  1. Double click the cell in the "Property Value" column and type the new value for the property.
  2. To commit the changed value to the JVM press enter. To cancel, press esc.
  3. If the current installed SecurityManager allows the user to edit the selected property, the property value will be changed. Otherwise an error message will be printed below the "Add Property" button.
5. To remove an existing property:
  1. Select the property that will be deleted and press the "Delete Property" button.
  2. A confirm prompt will appear: select "Yes" to delete the property and "No" to cancel.
  3. If "Yes" was clicked and the current installed SecurityManager allows the user to remove the selected property, the property value will be changed. Otherwise an error message will be printed below the "Add Property" button.

# Building
Requires Java Development Kit 7 or higher and Burp Suite jar file (Free or Professional)

1. Clone the Burp-JVM-Property-Editor repository.
2. Open a terminal and navigate to the directory containing the Burp-JVM-Property-Editor directory
3. Create a directory called build in order to store the generated Java .class files
4. Issue the following command to compile the extension: javac -cp [PATH_TO_BURP_JAR] -d build Burp-JVM-Property-Editor/burp/BurpExtender.java
5. Issue the following command to create the extension jar file (named burp-jvm-property-editor.jar): jar -vcf burp-jvm-property-editor.jar -C build .


Copyright (C) 2016 Jeff Cap (Bort_Millipede)
