'''
Hendra Soewarno (0119067305)
Honeypot pop3 ini tidak disertai pembatasan jumlah thread, sehingga perlu dilakukan
pembatasan pada level firewall.
/sbin/iptables  -A INPUT -p tcp --syn --dport 1110 -m connlimit --connlimit-above 50 -j REJECT
POPSvr mensimulasikan server pop untuk sebagai honeypot yang menarik penyerang
untuk melakukan bruteforce password. Honeypot akan merekam semua userid dan password
yang dicoba penyerang, sehingga menjadi early warning bagi administrator terkait dengan
userid/password yang compromis.
nohup python /path/to/pop3svr.py &
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
import base64

def plainText(auth):
    auth_bytes = auth.encode('ascii')
    base64_bytes = base64.b64encode(auth_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message
    
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
    
#support STLS
def chooseSocket(conn, TLSSSLconn):
    if (TLSSSLconn):
        return TLSSSLconn
    return conn    


def threaded_client(conn, address, count, logger, context):
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
    step = 0
    TLSSSLconn = None
    
    try:
        while True:       
            request=readRequest(chooseSocket(conn, TLSSSLconn))
            logger.info(request) 
            print(request)
            response='-ERR\r\n'
            if request.startswith(b"QUIT"):
                response='+OK signing off\r\n';
            elif request.upper().startswith(b"CAPA"):
                response='+OK\r\nSTLS\r\nUSER\r\nSASL PLAIN LOGIN\r\n'; 		
            elif request.upper().startswith(b"STLS"):
                response='+OK Begin TLS negotiation\r\n';
            #start user/pass
            elif request.upper().startswith(b"USER"):
                cmd = request.decode("utf-8")
                userid = cmd[5:-2]
                step=1
                response='+OK Password required\r\n';
            elif request.upper().startswith(b"PASS") and step==2:
                cmd = request.decode("utf-8")
                password = cmd[5:-2]
                if userid=="root" and password=="password":
                    step=6
                    response='+OK Logged in\r\n'
                else:
                    step=0
                    response='-ERR Authentication failed\r\n'
            #end user/pass
            #start auth plain
            elif request.upper().startswith(b"AUTH PLAIN"):
                response = "+\r\n"
                step=3
            elif step==3:    
                cmd = request.decode("utf-8")
                auth = cmd[0:-2]
                if auth==plainText("\0root\0password"):
                    step=6
                    response = "+OK Logged in\r\n"
                else:
                    response = "-ERR Authentication failed\r\n"
            #end auth plain            
            #start auth login
            elif request.upper().startswith(b"AUTH LOGIN"):
                response = "+ VXNlcm5hbWU6"
                step=4
            elif step==4:
                userid = request.decode("utf-8")[0:-2]
                response = "+ UGFzc3dvcmQ6"
                step=5
            elif step==5:
                password = request.decode("utf-8")[0:-2]
                if userid==plainText("root") and password==plainText("password"):
                    step=6
                    response = "+OK Logged in\r\n"
                else:
                    response = "-ERR Authentication failed\r\n"              
                step = 0
            #end auth login
            elif auth==6:
                if request.upper().startswith(b"STAT"):
                    response='+OK 1 100\r\n'
                elif request.upper().startswith(b"LIST") or request.upper().startswith(b"TOP"):
                    response='+OK 1 messages\r\n1 100\r\n.\r\n'
                elif request.upper().startswith(b"RETR"):
                    response='+OK messages follows\r\nDate: Fri, 26 Mar 2021 10:58:23 +0700\r\nFrom: admin@localhost\r\nTo: root@localhost\r\nContent-Type: text/plain; charset="utf-8"\r\nSubject: This is Testmail\r\n\r\nHello, mail from you Administrator.\r\nPlease ignore it.\r\n.\r\n'
                elif request.upper().startswith(b"RSET"):
                    response='+OK\r\n'		                    
                elif request.upper().startswith(b"DELE"):
                    response='+OK Message deleted\r\n'		
					
            chooseSocket(conn, TLSSSLconn).sendall(response.encode())
       
            if request.upper().startswith(b"STLS"):
                TLSSSLconn=context.wrap_socket(conn, server_side=True)       
            elif request.upper().startswith(b"QUIT"):
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
port = 1110
ThreadCount = 0

#create logger object
logger = logging.getLogger()
logger.setLevel(logging.INFO) 

#create logrotate daily, keep 30 days
handler = TimedRotatingFileHandler('HPOTpop3.log',
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

logger.info("POP3 HoneyPot " + VERSION + " ready at port " + str(port)) 
print("POP3 HoneyPot " + VERSION + " ready at port " + str(port)) 
ServerSocket.listen(5)

while True:
    Client, address = ServerSocket.accept()
    Client.settimeout(60)
    ThreadCount += 1
    start_new_thread(threaded_client, (Client, address, ThreadCount, logger, context))         
ServerSocket.close()
