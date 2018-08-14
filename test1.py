#!/usr/bin/python

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import os
import subprocess
import sys
import re

items = []

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
			alv = dict(Name=androdebug['Name'], owasp=androdebug['type'], issue=androdebug['info'], recom=androdebug['Recommendation'])
			items.append(alv)

		if 'android:allowBackup="True"' in line:
			alv = dict(Name=androbackup['Name'], owasp=androbackup['type'], issue=androbackup['info'], recom=androbackup['Recommendation'])
			items.append(alv)
			
		if 'android:exported="true"' in line:
			if 'activity' in line:
				result = re.search('android:name="(.*?)"', line).group(1)
				temp = androexportedactivity['Name'] + ":" + result
				alv = dict(Name=temp, owasp=androexportedactivity['type'], issue=androexportedactivity['info'], recom=androexportedactivity['Recommendation'])
				items.append(alv)

			elif 'service' in line:
				result = re.search('android:name="(.*?)"', line).group(1)
				temp = androexportedservice['Name'] + ":" + result
				alv = dict(Name=temp, owasp=androexportedservice['type'], issue=androexportedservice['info'], recom=androexportedservice['Recommendation'])
				items.append(alv)
				
			elif 'receiver' in line:
				result = re.search('android:name="(.*?)"', line).group(1)
				temp = androexportedbroadcast['Name'] + ":" + result
				alv = dict(Name=temp, owasp=androexportedbroadcast['type'], issue=androexportedbroadcast['info'], recom=androexportedbroadcast['Recommendation'])
				items.append(alv)
				
			elif 'provider' in line:
				result = re.search('android:name="(.*?)"', line).group(1)
				temp = androexportedcontent['Name'] + ":" + result
				alv = dict(Name=temp, owasp=androexportedcontent['type'], issue=androexportedcontent['info'], recom=androexportedcontent['Recommendation'])
				items.append(alv)
				
		if 'android:launchMode="singleTop"' in line:
			alv = dict(Name=androlaunchmode['Name'], owasp=androlaunchmode['type'], issue=androlaunchmode['info'], recom=androlaunchmode['Recommendation'])
			items.append(alv)
			
		elif 'android:launchMode="singleTask"' in line:
			alv = dict(Name=androlaunchmode['Name'], owasp=androlaunchmode['type'], issue=androlaunchmode['info'], recom=androlaunchmode['Recommendation'])
			items.append(alv)

		elif 'android:launchMode="singleInstance"' in line:
			alv = dict(Name=androlaunchmode['Name'], owasp=androlaunchmode['type'], issue=androlaunchmode['info'], recom=androlaunchmode['Recommendation'])
			items.append(alv)

		if 'android:testOnly="True"' in line:
			alv = dict(Name=androtestmode['Name'], owasp=androtestmode['type'], issue=androtestmode['info'], recom=androtestmode['Recommendation'])
			items.append(alv)

		if 'android:taskAffinity' in line:
			alv = dict(Name=androtaskaffinity['Name'], owasp=androtaskaffinity['type'], issue=androtaskaffinity['info'], recom=androtaskaffinity['Recommendation'])
			items.append(alv)

env = Environment(loader=FileSystemLoader('.'))
template = env.get_template("myreport.html")
html_out = template.render(items=items)
HTML(string=html_out).write_pdf("report.pdf")
print "The report has been generated and saved in the current direcotry with the name report.pdf"
