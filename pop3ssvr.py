'''
Hendra Soewarno (0119067305)
Honeypot pop3s ini tidak disertai pembatasan jumlah thread, sehingga perlu dilakukan
pembatasan pada level firewall.
/sbin/iptables  -A INPUT -p tcp --syn --dport 9995 -m connlimit --connlimit-above 50 -j REJECT
POPSvr mensimulasikan server pop untuk sebagai honeypot yang menarik penyerang
untuk melakukan bruteforce password. Honeypot akan merekam semua userid dan password
yang dicoba penyerang, sehingga menjadi early warning bagi administrator terkait dengan
userid/password yang compromis.
nohup python /path/to/pop3ssvr.py &
'''
#!/usr/bin/env python3
import time
import datetime  
import socket
import ssl
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
	
def readBody(conn):
    text = b""
    try:
        conn.settimeout(0.1)
        while True:
            data = conn.recv(1)
            if not data:
                break
            text += data
    except:
        return text	
    return text

def threaded_client(conn, address, count, logger):
    #print (conn.getsockname())
    serverAddr = conn.getsockname()[0]
    clientAddr = address[0]
    logger.info(str(count)+"@"+clientAddr + " -> connected to " + serverAddr) 
    print(str(count)+"@"+clientAddr + " -> connected to " + serverAddr)
    time.sleep(2) # Sleep for 2 seconds
    strwelcome = b"+OK Hello there.\r\n"
    conn.sendall(strwelcome)
    userid = ""
    password = ""
    auth = 0
    try:
        while True:       
            request=readRequest(conn)
            logger.info(request) 
            print(request)
            response='-ERR\r\n'
            if request.startswith(b"QUIT"):
                response='+OK signing off\r\n';
            elif request.startswith(b"USER"):
                cmd = request.decode("utf-8")
                userid = cmd[5:-2]
                response='+OK Password required\r\n';
            elif request.startswith(b"PASS"):
                cmd = request.decode("utf-8")
                password = cmd[5:-2]
                #if userid=="root" and password=="password":
                if password=="password":
                    auth=1
                    response='+OK logged in.\r\n'
            elif auth==1:
                if request.startswith(b"STAT"):
                    response='+OK 1 100\r\n'
                elif request.startswith(b"LIST") or request.startswith(b"TOP"):
                    response='+OK 1 messages\r\n1 100\r\n.\r\n'
                elif request.startswith(b"RETR"):
                    response='+OK messages follows\r\nDate: Fri, 26 Mar 2021 10:58:23 +0700\r\nFrom: admin@localhost\r\nTo: root@localhost\r\nContent-Type: text/plain; charset="utf-8"\r\nSubject: This is Testmail\r\n\r\nHello, mail from you Administrator.\r\nPlease ignore it.\r\n.\r\n'
                elif request.startswith(b"DELE"):
                    response='+OK Message deleted\r\n'				

            print(response)					
            conn.sendall(response.encode())
			
            if request.startswith(b"QUIT"):
                raise Exception("Client QUIT")
    except Exception as e:
        logger.info(str(count)+"@"+clientAddr + " -> " + str(e))
        print(str(count)+"@"+clientAddr + " -> " + str(e))
        conn.close()
    logger.info(str(count)+"@"+clientAddr + " -> disconnected")
    print(str(count)+"@"+clientAddr + " -> disconnected")

#entry point
VERSION = "0.1a"


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
#buat file pem dan key dari https://www.samltool.com/self_signed_certs.php
context.load_cert_chain('certchain.pem', 'private.key')

ServerSocket = socket.socket()
host = "0.0.0.0"
port = 9995
ThreadCount = 0

#create logger object
logger = logging.getLogger()
logger.setLevel(logging.INFO) 

#create logrotate daily, keep 30 days
handler = TimedRotatingFileHandler('HPOTpop3s.log',
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

logger.info("POP3s HoneyPot " + VERSION + " ready at port " + str(port)) 
print("POP3s HoneyPot " + VERSION + " ready at port " + str(port)) 
ServerSocket.listen(5)

SecureServerSocket=context.wrap_socket(ServerSocket, server_side=True)

while True:
    Client, address = SecureServerSocket.accept()
    Client.settimeout(15)
    ThreadCount += 1
    start_new_thread(threaded_client, (Client, address, ThreadCount, logger))        
ServerSocket.close()

