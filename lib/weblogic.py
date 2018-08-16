#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-08-09 10:14:05
# @Author  : luoshu (luovxv@gamil.com)
# @Link    : https://www.gitshell.org


import requests

def WeakScan(host,port):
    url = "http://%s:%s/console/j_security_check" % (host,str(port))
    flag = ['console/console.portal','WebLogic Server Console','console-help.js','Home Page','console/jsp/common/warnuserlockheld.jsp','/console/actions/common/']
    username = ['weblogic','system','admin']
    password = ['weblogic','welcome1','weblogic123','11111111','12345678']
    for user in username:
        for pwd in password:
            data = {'j_username':user ,'j_password':pwd,'j_character_encoding':'UTF-8'}
            try:
                req = requests.post(url=url, data=data, timeout=10)
                content = req.text
                for f in flag:
                    if f in content:
                        return(user+':'+pwd)
                    else:
                        #print('error==>'+user+':'+pwd)
                        continue
            except Exception as e:
                break


