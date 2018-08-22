# lMaekScan

lMaekScan 简单的口令爆破攻击，针对端口自动化检测：
>端口探测->中间件识别->口令爆破

目前可检测: tomcat,weblogic,jboss,resin,glassfish

### 环境配置
- 需安装nmap(>=7.40)
- python3.*
- pip install -r requirements.txt

### 使用试例
- -f 参数：指定ip列表文件
- -t 参数：指定线程,未指定使用默认线程50
- -i 参数：指定ip(192.168.1.1)或ip范围(192.168.1.1/24 or 192.168.1.1-192.168.1.254)
- -p 参数：指定端口(1-65535 or 80,8080),未指定端口扫描 80-10000

例子：
> python lWeakScan.py -f host.txt -t 100 -p 80-10000

> python lWeakScan.py -i 192.168.1.1/24

> python lWeakScan.py -i 192.168.1.1  -p 1-65535

请勿用于非法用途，用于非法用途与本人无关