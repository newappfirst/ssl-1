#!/usr/bin/env python
import subprocess
import sys
import os
import time

if(len(sys.argv)<4):
    print "Usage:"+sys.argv[0]+" host port cacert"
    sys.exit(1)
host = sys.argv[1]
port = sys.argv[2]
error = 0
p = subprocess.Popen('google-chrome --incognito --ignore-certificate-errors'+' https://'+host+":"+port, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
errormsg = "CERT_PKIXVerifyCert for "+host+" failed err="
#no easy way to know when chrome is done with the handshake
time.sleep(0.5)
p.terminate()
#os.system("killall chrome")
for line in p.stderr.readlines():
    pos=line.find(errormsg)
    if (pos!=-1):
	errcode = line[pos+len(errormsg):]
	print errcode
	error=1
	break

if (error==0):
    print "0"
retval = p.wait()
sys.exit(retval)
