#!/usr/bin/python

#coding: utf-8

import os
import subprocess
import sys
import re


androdebug = {'Name': 'Android Debuggable is Enabled for App', 'type': 'OWASP M8 Code Tampering', 'info': 'Debugging was enabled on the app which makes it easier for reverse engineers to hook a debugger to it. This allows dumping a stack trace and accessing debugging helper classes', 'Recommendation': 'Turn android debuggable off by setting the flag as false in the manifest file'}

androbackup = {'Name': 'Application Data can be backed Up', 'type': 'OWASP M2 Insecure Data Storage', 'info':'This flag allows anyone to backup your application data via adb. It allows users who have enabled USB debugging to copy application data off of the device.', 'Recommendation':'Set android allowbackup to false in the manifest file'}

androexportedactivity = {'Name': 'The following activities are exported from the application', 'type': 'OWASP M7 Poor code Quality', 'info':'An activity represents a single screen with a user interface. Activity serves as the entry point for a users interaction with an app and is also central to how a user navigates within an app or between apps. Exported activities with some critical functionalities would allow a malicious application to bypass the protection controls in place to prevent unauthorized access.', 'Recommendation':'Disable the exported flag for the activity in the manifest file'}

androexportedservice = {'Name': 'The following services are exported from the application', 'type': 'OWASP M7 Poor code Quality', 'info':'A service is a component that runs in the background to perform long-running operations or to perform work for remote processes. Exporting the application services would allow a malicious application to run these components in the background without explicit consent from the user thus aming the data handled by the application vulnerable.', 'Recommendation':'Disable the exported flag for the service in the manifest file'}

androexportedbroadcast = {'Name': 'The following broadcast receivers are exported', 'type': 'OWASP M7 Poor code Quality', 'info':'A Broadcast Receiver is an Android Component which allows you to register for system or application events. If this feature is enabled in the application, the application can make system calls and receive information through these calls.', 'Recommendation':'Disable the exported flag for the broadcast receiver in the manifest file'}

androexportedcontent = {'Name': 'The following content providers are exported', 'type': 'OWASP M7 Poor code Quality', 'info':'Content Provider component supplies data from one application to others on request. Through the content provider, other apps can query or even modify the data. Thus exported content providers in an app would leave the data handeld by the applictaion vulnerable to a malious application.', 'Recommendation':'Disable the exported flag for the content provider in the manifest file'}

androlaunchmode = {'Name': 'Launch mode of the activity is not standard', 'type': 'OWASP TBD', 'info':'By not setting the launch mode of the activity as standard, the intents might be sent to the existing activities on top of the stack trace .New activities should always be created to work separately with each Intent sent.', 'Recommendation':'Set the launch mode of the activity to standard'}

androtestmode = {'Name': 'The application has test mode enabled', 'type': 'OWASP N/A', 'info':'The application is specfied still in test mode. This flag would make the application unusable on some devices which prohibits running of test applications.', 'Recommendation':'Disable the test mode flag for the app before launch'}

androtaskaffinity = {'Name': 'Task affinity is set for the app', 'type': 'OWASP M1 Improper Platform Usage', 'info':'Task affinity specifies which task that the activity desires to join. By default, all activities in an app have the same affinity which is the app package name. IF the default values are not changed then the attackers might use this to mount attacks like task hijacking', 'Recommendation':'Redefine the task affinity of the application to acheive desirable task behaviour'}

val1 = sys.argv[1]
asdf = val1[:-4]
abcd = "./" + asdf
#subprocess.call(["apktool", "d", val1])
try:
	sys.stdout.write("Trying to decompile the apk \n")
	subprocess.check_output(['apktool', 'd', val1])
	sys.stdout.flush()
except subprocess.CalledProcessError:
	print "There was an error processing the file"

def searchmanifest():
	for dlist, sublist, flist in os.walk(abcd):
		for fname in flist:
			if fname == "AndroidManifest.xml":
				return dlist + "/" + fname


manifest = searchmanifest()
#fileread = open(manifest).read()
with open(manifest, "r") as ins:
	for line in ins:
		if 'android:debuggable="true"' in line:
			print androdebug['Name']
			print "OWASP: " + androdebug['type']
			print "Issue info: " + androdebug['info']
			print "Recommendation: " + androdebug['Recommendation']
			print " "

		if 'android:allowBackup="True"' in line:
			print androbackup['Name']
			print "OWASP: " + androbackup['type']
			print "Issue info: " + androbackup['info']
			print "Recommendation: " + androbackup['Recommendation']
			print " "

		if 'android:exported="true"' in line:
			if 'activity' in line:
				cat = 'Activity'
				result = re.search('android:name="(.*)"', line).group(1)
				print androexportedactivity['Name']
				print result
				print "OWASAP: " + androexportedactivity['type']
				print "Issue info:" + androexportedactivity['info']
				print "Recommendation: " + androexportedactivity['Recommendation']
				print " "

			elif 'service' in line:
				result = re.search('android:name="(.*)"', line).group(1)
				print androexportedservice['Name']
				print result
				print "OWASAP: " + androexportservice['type']
				print "Issue info:" + androexportedservice['info']
				print "Recommendation: " + androexportedservice['Recommendation']
				print " "

			elif 'receiver' in line:
				cat = 'Recevier'
				result = re.search('android:name="(.*)"', line).group(1)
				print androexportedbroadcast['Name']
				print result
				print "OWASAP: " + androexportedbroadcast['type']
				print "Issue info:" + androexportedbroadcast['info']
				print "Recommendation: " + androexportedbroadcast['Recommendation']
				print " "

			elif 'provider' in line:
				cat = 'Recevier'
				result = re.search('android:name="(.*)"', line).group(1)
				print androexportedcontent['Name']
				print result
				print "OWASAP: " + androexportedcontent['type']
				print "Issue info:" + androexportedcontent['info']
				print "Recommendation: " + androexportedcontent['Recommendation']
				print " "

		if 'android:launchMode="singleTop"' in line:
			print androlaunchmode['Name']
			print "OWASP: " + androlaunchmode['type']
			print "Issue info: " + androlaunchmode['info']
			print "Recommendation: " + androlaunchmode['Recommendation']
			print " "
		elif 'android:launchMode="singleTask"' in line:
			print androlaunchmode['Name']
			print "OWASP: " + androlaunchmode['type']
			print "Issue info: " + androlaunchmode['info']
			print "Recommendation: " + androlaunchmode['Recommendation']
			print " "
		elif 'android:launchMode="singleInstance"' in line:
			print androlaunchmode['Name']
			print "OWASP: " + androlaunchmode['type']
			print "Issue info: " + androlaunchmode['info']
			print "Recommendation: " + androlaunchmode['Recommendation']
			print " "

		if 'android:testOnly="True"' in line:
			print androtestmode['Name']
			print "OWASP: " + androtestmode['type']
			print "Issue info: " + androtestmode['info']
			print "Recommendation: " + androtestmode['Recommendation']
			print " "

		if 'android:taskAffinity' in line:
			print androtaskaffinity['Name']
			print "OWASP: " + androtaskaffinity['type']
			print "Issue info: " + androtaskaffinity['info']
			print "Recommendation: " + androtaskaffinity['Recommendation']
			print " "
		
	



