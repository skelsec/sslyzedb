# sslyzedb
Database and reporting backed for sslyze


# Install
Fetch it from github then 
  
```
setup.py install
```

OR  
  
```
pip install sslyzedb
```

# Howto
There are a few steps to take to fire this up!
   
### Create The database
You'd need to have a database set up OR specify an SQLite db file that will be created.
Database connection string can be submitted either via command line ```--sql``` or by setting the SSLYZEDB environment variable
  
Example:
```
sslyzedb --sql sqlite:///test.db db create
```
### Create a project
The project is there so you can group your scans. Not really used currently but might be good for the future.
You will have to note the project ID, this will be used to identify the project later.
  
Example:
```
sslyzedb --sql sqlite:///test.db createproject testproject
```
### Create a scan for your project


Example:
The following command creates an empty scan for project id '1'
```
sslyzedb --sql sqlite:///test.db createscan 1
```
### Add targets to your scan
In this step you must specify the target servers in <IP/domainname>:<port> format. And assign them to a scan.  
The script accepts targets via the command line or via a file, where each target is in a separate line.  
Remember the scan ID I told you to keep note of, right?
  
Example:
```
sslyzedb --sql sqlite:///test.db addtarget 1 file targets.txt
```
### Add scan commands to your scans
These commands will be performed against all targets specified in the previous step.  
At this moment only the 'ALL' command is tested.
  
Example:
```
sslyzedb --sql sqlite:///test.db addcommand 1 ALL
```
### START THE SCANNER
Command below will start the scan job for scan id 1

Example:
```
sslyzedb --sql sqlite:///test.db scan 1
```
### Get the report
When scanning is finished the results are stored in the DB. You'll need to use the scan id to pull the report.
Report is in TSV format.

Example:
```
sslyzedb --sql sqlite:///test.db report 1
```

# Requirements
* Python3.6
* SSLYze
* sqlalchemy

# Kudos
Alban Diquet for teh awesome [SSLyze](https://github.com/nabla-c0d3/sslyze) tool!  
