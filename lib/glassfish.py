#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-08-09 10:14:05
# @Author  : luoshu (luovxv@gamil.com)
# @Link    : https://www.gitshell.org

import requests

def WeakScan(host,port):
    flag = ['Common Tasks','/resource/common/js/adminjsf.js','/common/index.jsf','Logout from GlassFish Administration Console','GlassFish Console - Common Tasks']
    username = ['admin','system','glassfish','root']
    password = ['admin','admin123','admin888','adminadmin','123456','12345678','0123456789','111111','glassfish','root','passwor','manager']
    for user in username:
        for pwd in password:
            url = "https://%s:%s/common/j_security_check" % (host,str(port))
            data = {'j_username':user,'j_password':pwd,'loginButton':'Login','loginButton.DisabledHiddenField':'true'}
            try:
                requests.packages.urllib3.disable_warnings()
                req = requests.post(url=url,data=data,timeout=10,verify=False)
                req_text = req.text
            except Exception as e:
                break
            for f in flag:
                if f in req_text:
                    return(user+':'+pwd)

    for user in username:
        for pwd in password:
            url = "http://%s:%s/common/j_security_check" % (host,str(port))
            data = {'j_username':user,'j_password':pwd,'loginButton':'Login','loginButton.DisabledHiddenField':'true'}
            try:
                req = requests.post(url=url,data=data,timeout=10,verify=False)
                req_text = req.text
            except Exception as e:
                break
            for f in flag:
                if f in req_text:
                    return(user+':'+pwd)                
