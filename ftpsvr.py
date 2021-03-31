'''
Hendra Soewarno (0119067305)
Honeypot http ini tidak disertai pembatasan jumlah thread, sehingga perlu dilakukan
pembatasan pada level firewall.
/sbin/iptables  -A INPUT -p tcp --syn --dport 2121 -m connlimit --connlimit-above 50 -j REJECT
FtpSvr mensimulasikan server ftp untuk sebagai honeypot yang menarik penyerang
untuk melakukan bruteforce password. Honeypot akan merekam semua userid dan password
yang dicoba penyerang, sehingga menjadi early warning bagi administrator terkait dengan
userid/password yang compromis.
nohup python /path/to/ftpsvr.py &
'''
#!/usr/bin/env python3
import time
import datetime  
import socket
import os
import logging
from logging.handlers import TimedRotatingFileHandler
from _thread import *

def readRequest(conn):
    text = b""
    while not text.endswith(b"\r\n"):
        data = conn.recv(1)
        if not data:
            raise Exception("disconnect from client")
        text += data
    return text
	
def threaded_client(conn, address, count, logger):
    #print (conn.getsockname())
    directory = "include"
    serverAddr = conn.getsockname()[0]
    clientAddr = address[0]
    logger.info(str(count)+"@"+clientAddr + " -> connected to " + serverAddr) 
    print(str(count)+"@"+clientAddr + " -> connected to " + serverAddr)
    time.sleep(2) # Sleep for 2 seconds
    strwelcome = b"220 Welcome to FTP server\r\n"
    conn.sendall(strwelcome)
    cwd = "/var/www"
    auth = 0
    userid = ""
    password = ""
    dataAddr = ""
    dataPort = 0
    try:
        while True:       
            request=readRequest(conn)
            logger.info(request) 
            print(request)
            response='500 Sorry.\r\n';
            if request.startswith(b"QUIT"):
                response='221 Goodbye.\r\n';
            elif request.lower().startswith(b"OPTS"):
                response='200 OK.\r\n';
            elif request.lower().startswith(b"SYST"):
                response='215 UNIX Type: L8.\r\n';				
            elif request.startswith(b"USER"):
                cmd = request.decode("utf-8")
                userid = cmd[5:-2]
                response='331 OK.\r\n';
            elif request.startswith(b"PASS"):
                cmd = request.decode("utf-8")
                password = cmd[5:-2]
                #if userid=="root" and password=="password":
                if password=="password":				
                    auth=1
                    response='230 OK.\r\n';
                else:
                    response='430 invalid user or password.\r\n';
            elif request.lower().startswith(b"NOOP"):
                response='200 OK.\r\n';
            elif request.startswith(b"TYPE"):
                response='200 Binary mode.\r\n';
            elif request.startswith(b"PASV"):
                response='502 Command not implemented.\r\n';							
				
            if auth==1:    
                if request.startswith(b"PWD") or request.startswith(b"XPWD"):
                    response='257 \"' + cwd + '"\r\n';
                elif request.startswith(b"PORT"):
                    response='200 Transfer starting.\r\n';
                    cmd = request.decode("utf-8")
                    l=cmd[5:].split(',')
                    dataAddr='.'.join(l[:4])
                    dataPort=(int(l[4])<<8)+int(l[5])
                elif request.startswith(b"LIST") or request.startswith(b"NLST"):	
                    conn.sendall(b'150 directory listing.\r\n')
                    datasock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                    datasock.connect((dataAddr,dataPort))
                    #datasock.sendall(b"\r\n-rw-r--r-- 1 root root     1555 Apr 20  2016 index.html\r\n\r\n")        
				
                    ls=os.listdir(directory)
                    for fn in ls:
                        st=os.stat(directory + "/" + fn)
                        fullmode='rwxrwxrwx'
                        mode=''
                        for i in range(9):
                            mode+=((st.st_mode>>(8-i))&1) and fullmode[i] or '-'
                        dir=(os.path.isdir(fn)) and 'd' or '-' 
                        ftime=time.strftime(' %b %d  %Y ', time.gmtime(st.st_mtime))
                        fdetails = dir+mode+' 1 www-data www-data '+str(st.st_size).rjust(9,' ')+ftime+fn				
                        print(fdetails)
                        datasock.sendall(fdetails.encode())
                        datasock.sendall(b"\r\n")
                 		
                    datasock.close()
                    response='226 Directory send OK.\r\n'
                elif request.startswith(b"RETR"):
                    cmd = request.decode("utf-8")			
                    fn=cmd[5:-2]
                    print('GET:'+fn)
                    try:
                        file=open(directory + "/"+fn,'rb')
                        conn.sendall(b'150 Opening data connection.\r\n')
                        datasock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        datasock.connect((dataAddr,dataPort))
                        data= file.read(1024)
                        while data:
                            datasock.sendall(data)
                            data=file.read(1024)
                        file.close()					
                        datasock.close()
                        response='226 Transfer complete.\r\n'
                    except IOError:
                        response='500 File not found.\r\n';
                
                elif request.startswith(b"STOR"):
                    cmd = request.decode("utf-8")
                    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%b%d%H%M%S") + "."
                    fn=cmd[5:-2].replace(".",now,1)
                    print('PUT:'+fn)
                    file=open(directory + "/"+fn,'wb')
                    conn.sendall(b'150 Opening data connection.\r\n')
                    datasock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                    datasock.connect((dataAddr,dataPort))
                    datasock.settimeout(0.1)
                    while True:
                        data = datasock.recv(1024)
                        if not data:
                            break
                        file.write(data)
                    file.close()
                    datasock.close()
                    response='226 Transfer complete.\r\n'				
	
            conn.sendall(response.encode())
			
            if request.startswith(b"QUIT"):
                auth=0
                raise Exception("Client QUIT")
				
    except Exception as e:
        logger.info(str(count)+"@"+clientAddr + " -> " + str(e))
        print(str(count)+"@"+clientAddr + " -> " + str(e))
        conn.close()
    logger.info(str(count)+"@"+clientAddr + " -> disconnected")
    print(str(count)+"@"+clientAddr + " -> disconnected")

#entry point
VERSION = "0.1a"

ServerSocket = socket.socket()
host = "0.0.0.0"
port = 2121
ThreadCount = 0

#create logger object
logger = logging.getLogger()
logger.setLevel(logging.INFO) 

#create logrotate daily, keep 30 days
handler = TimedRotatingFileHandler('HPOTftp.log',
    when='midnight',
    interval=1,
    backupCount=30)
	
log_format="%(asctime)s %(levelname)s %(threadName)s %(message)s"	
handler.setFormatter(logging.Formatter(log_format))	
logger.addHandler(handler)

try:
    ServerSocket.bind((host, port))
except Exception as e:
    print(str(e))

logger.info("FTP HoneyPot " + VERSION + " ready at port " + str(port))  
print("FTP HoneyPot " + VERSION + " ready at port " + str(port))  
ServerSocket.listen(5)

while True:
    Client, address = ServerSocket.accept()
    Client.settimeout(120)
    ThreadCount += 1
    start_new_thread(threaded_client, (Client, address, ThreadCount, logger))        
ServerSocket.close()
