'''
Hendra Soewarno (0119067305)
Honeypot FTP ini tidak disertai pembatasan jumlah thread, sehingga perlu dilakukan
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
from pathlib import Path

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
    pasv = False
    nextSocket = None
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
            if auth==1:    
                if request.startswith(b"PWD") or request.startswith(b"XPWD"):
                    response='257 \"' + cwd + '"\r\n';
                elif request.startswith(b"CWD"):
                    response='250 CWD command successful.\r\n';
                elif request.startswith(b"PASV"):
                    #response='502 Command not implemented.\r\n';
                    pasv=True
                    nextSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                    nextSocket.bind((serverAddr,61200 + (count%1024))) #port >= 61200 s/d 62004
                    nextSocket.listen(1)
                    ip, port = nextSocket.getsockname()
                    response='227 Entering Passive Mode (%s,%u,%u).\r\n' % (','.join(ip.split('.')), port>>8&0xFF, port&0xFF)
                    print(response)
                    
                elif request.startswith(b"PORT"):                
                    pasv=False
                    response='200 Transfer starting.\r\n';
                    cmd = request.decode("utf-8")
                    l=cmd[5:].split(',')
                    dataAddr='.'.join(l[:4])
                    dataPort=(int(l[4])<<8)+int(l[5])
                    nextSocket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                    
                elif request.startswith(b"LIST") or request.startswith(b"NLST"):	
                    conn.sendall(b'150 directory listing.\r\n')
                    #datasock.sendall(b"\r\n-rw-r--r-- 1 root root     1555 Apr 20  2016 index.html\r\n\r\n")        
                    
                    if pasv:
                        sock, addr = nextSocket.accept() #PASV mode
                        sock.settimeout(60)
                    else:
                        nextSocket.connect((dataAddr,dataPort))
                        sock = nextSocket
                    
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
                        sock.sendall(fdetails.encode())
                        sock.sendall(b"\r\n")
                 		
                    sock.close()
                    response='226 Directory send OK.\r\n'
                elif request.startswith(b"RETR"):
                    cmd = request.decode("utf-8")			
                    fn=Path(cmd[5:-2]).name
                    print('GET:'+fn)
                    try:
                        file=open(directory + "/"+fn,'rb')
                        conn.sendall(b'150 Opening data connection.\r\n')
                        
                        if pasv:
                            sock, addr = nextSocket.accept() #PASV mode
                            sock.settimeout(60)
                        else:
                            nextSocket.connect((dataAddr,dataPort))
                            sock = nextSocket
                    
                        data= file.read(1024)
                        while data:
                            sock.sendall(data)
                            data=file.read(1024)
                        file.close()					
                        sock.close()
                        response='226 Transfer complete.\r\n'
                    except IOError:
                        response='500 File not found.\r\n';
                
                elif request.startswith(b"STOR"):
                    cmd = request.decode("utf-8")
                    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "."
                    fn=Path(cmd[5:-2]).name.replace(".",now,1)
                    print('PUT:'+fn)
                    file=open(directory + "/"+fn,'wb')
                    conn.sendall(b'150 Opening data connection.\r\n')

                    if pasv:
                        sock, addr = nextSocket.accept() #PASV mode
                        sock.settimeout(60)
                    else:
                        nextSocket.connect((dataAddr,dataPort))
                        sock = nextSocket
                    
                    sock.settimeout(0.1)
                    while True:
                        data = sock.recv(1024)
                        if not data:
                            break
                        file.write(data)
                    file.close()
                    sock.close()
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
logger.info("Please open firewall Port for PASV 61200 to 62004") 
print("FTP HoneyPot " + VERSION + " ready at port " + str(port)) 
print("Please open firewall Port for PASV 61200 to 62004")  
ServerSocket.listen(5)

while True:
    Client, address = ServerSocket.accept()
    Client.settimeout(60)
    ThreadCount += 1
    start_new_thread(threaded_client, (Client, address, ThreadCount, logger))        
ServerSocket.close()