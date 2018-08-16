#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-08-09 10:14:05
# @Author  : luoshu (luovxv@gamil.com)
# @Link    : https://www.gitshell.org

import time
import base64
import requests


def WeakScan(host,port):
    flag = ['Application Manager','HTML Manager Help','Welcome to Tomcat']
    username = ['admin','tomcat','manager','test','apache','root','admin888']
    password = ['','123456','tomcat','password','123456789','12345678','0123456789','123123','admin123','admin888','root','apache']
    url = 'http://%s:%s/manager/html' % (host,str(port))
    for user in username:
        for pwd in password:
            constr = user+':'+pwd
            #print(constr)
            bas64constr = base64.b64encode(constr.encode('utf-8'))
            b64str = bas64constr.decode('utf-8')
            #print(b64str)
            headers = {
                "Cache-Control": "max-age=0",
                "Authorization": "Basic "+b64str ,
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Connection": "close",
            }
            try:
                req = requests.get(url=url,headers=headers,timeout=10)
                req_code = req.status_code
                req_text = req.text
            except Exception as e:
                break
            if int(req_code) == 200:
                for f in flag:
                    if f in req.text:
                        return(constr)
            elif int(req_code) == 404:
                break
            elif int(req_code) == 403:
                break
            elif int(req_code) == 401:
                continue    

