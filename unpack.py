#/usr/bin/python

import subprocess
import sys


val1 = sys.argv[1]
#subprocess.call(["apktool", "d", val1])
try:
	sys.stdout.write("Trying to decompile the apk \n")
	subprocess.check_output(['apktool', 'd', val1])
	sys.stdout.flush()
except subprocess.CalledProcessError:
	print "There was an error processing the file"


