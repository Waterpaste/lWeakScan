#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-08-09 10:14:05
# @Author  : luoshu (luovxv@gamil.com)
# @Link    : https://www.gitshell.org
import argparse
import nmap
import sys
import json
import threading
import lib 
import requests
import time
from progressbar import *
from queue import Queue
sys.path.append("lib")


#单个ip/网段扫描
def ipscan(host,p):
    nm = nmap.PortScanner()
    print("Please be patient, the scan time may be too long ......")
    nm.scan(hosts=host, ports=p, arguments='-sV')
    print(nm.command_line())
    for survive in nm.all_hosts():
        if not nm[survive].all_tcp():
            continue
        else:
            for port in nm[survive].all_tcp():
                if nm[survive].tcp(port)["product"] == '':
                    continue
                else:
                    judgment(survive,port,nm[survive].tcp(port)["product"])


#file目标扫描
def portinfos(p,quantity):
    while True:
        try:
            host = queue.get(timeout=0.1)
            global num
            nma = nmap.PortScannerAsync()
            apple = nma.scan(hosts=host, arguments='-sV -p '+p,callback=callback_result)
            while nma.still_scanning():
                nma.wait(100)
        except Exception as e:
            break
        queue.task_done()
        progress(quantity)



def callback_result(host, scan_data):
    #print('------------------')
    if not scan_data['scan']:
        pass
    else:
        for x in scan_data['scan'][host]['tcp']:
            if(scan_data['scan'][host]['tcp'][x]['product'] == ''):
                continue
            else:
                judgment(host,x,scan_data['scan'][host]['tcp'][x]['product'])

#调用暴力破解
def judgment(host,port,values):
    values = values.lower()
    flag = ['weblogic','tomcat','jboss','resin','glassfish']
    for x in flag:
        x = x.lower()
        if values.find(x) != -1:
            if(x == 'tomcat'):
                url = 'http://%s:%s' % (host,str(port))
                re_html = requests.get(url=url,timeout=10).text
                if 'jboss' in re_html:
                    x = 'jboss'
            imp = __import__(x)
            con = imp.WeakScan(host,port)
            if not con:
                continue
            else:
                #lock.acquire()
                # global num               
                # num += 1
                fp = open("suc_host.txt",'a')
                #print('%s:%s is %s  success %s ' % (host,port,x,con))
                localtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                fp.write(str(localtime)+'---'+host+':'+str(port)+' success: '+con+'\n')
                fp.close()
                #lock.release()


def progress(quantity):
    with lock:       
        pbar.maxval = quantity
        finished = pbar.maxval - queue.unfinished_tasks
        pbar.update(finished)
        time.sleep(0.1)

#f 参数处理
def filetar(file,p):
    file = args.f
    p = args.p
    gethost(file)
    threads = [threading.Thread(target=portinfos, args=(p,queue.unfinished_tasks,)) for i in range(int(threadnum))]
    list(map(lambda x:x.start() ,threads))
    list(map(lambda x:x.join() ,threads))
    

def gethost(file):
    for x in open(file).readlines():
        file = x.strip()
        if not file:
            continue
        for ip in file.split():
            queue.put(ip)


def args():
    arg = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,description='Weak password scanner.(https://www.gitshell.org)',usage='scan.py [options]')
    arg.add_argument('-f',metavar='File',type=str,help='Add targets with files')
    arg.add_argument('-t',metavar='THREADS',type=int,default=50,help='Num of scan threads, 50 by default')
    arg.add_argument('-i',metavar='IP',type=str,help='Single IP scan OR Segment scan, For example: 192.168.1.1 or 192.168.1.1/24')
    arg.add_argument('-p',metavar='port',type=str,default='80-10000',help='Scan port ,For example: 1-65535 or 80,8080,')
    args = arg.parse_args()
    return args

if __name__ == '__main__':
    if len(sys.argv) == 1:
        sys.argv.append('--help')
    args = args()
    threadnum = args.t
    #num = 0
    if args.f:
        queue = Queue()
        lock = threading.Lock()
        widgets = ['Scanning:', Percentage(), ' ',Bar(marker=RotatingMarker()),' ', Timer(), ' ', ' ']
        pbar = ProgressBar(widgets=widgets, maxval=1).start()
        filetar(args.f,args.p)
        pbar.finish()
        #print(num)
    elif args.i:
        ipscan(args.i,args.p)
    print('==='*30)
    print('Scan is complete, please check the suc_host.txt file.') 

