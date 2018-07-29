#!/usr/bin/python

import os



androdebug = {'Name': 'Android Debuggable is Enabled for App', 'type': 'OWASP M2- Broken Authentication and Session Management', 'info': 'Debugging was enabled on the app which makes it easier for reverse engineers to hook a debugger to it. This allows dumping a stack trace and accessing debugging helper classes', 'Recommendation': 'Turn debuggable off'}

def searchmanifest():
	for dlist, sublist, flist in os.walk("."):
		for fname in flist:
			if fname == "AndroidManifest.xml":
				return dlist + "/" + fname


manifest = searchmanifest()
fileread = open(manifest).read()
if 'android:debuggable="true"' in fileread:
	print androdebug['Name']
	print androdebug['type']
	print androdebug['info']
	print androdebug['Recommendation']
	
else: 
	print "false"
	



