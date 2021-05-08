'''
Hendra Soewarno (0119067305)
Honeypot SMTP ini tidak disertai pembatasan jumlah thread, sehingga perlu dilakukan
pembatasan pada level firewall.
/sbin/iptables  -A INPUT -p tcp --syn --dport 2525 -m connlimit --connlimit-above 50 -j REJECT
SMTPSvr mensimulasikan server smtp untuk sebagai honeypot yang menarik penyerang
untuk melakukan bruteforce password. Honeypot akan merekam semua userid dan password
yang dicoba penyerang, sehingga menjadi early warning bagi administrator terkait dengan
userid/password yang compromis.
nohup python /path/to/smtpsvr.py &
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

def queueNo():
    return round(time.time() * 1000) % 100

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
        conn.settimeout(5)
        while not text.endswith(b"\r\n.\r\n"):
            data = conn.recv(1)
            if not data:
                break
            text += data
    except:
        return text	
    return text
    
#support STARTTLS
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
    strwelcome = b"220 SMTP Server Ready\r\n"
    conn.sendall(strwelcome)
    data = False
    TLSSSLconn = None

    try:
        while True:
            if not data:
                request=readRequest(chooseSocket(conn, TLSSSLconn))
            else:
                request=readBody(chooseSocket(conn, TLSSSLconn))
            logger.info(request) 
            print(request)
            response='502 Command not implemented\r\n'
            if request.upper().startswith(b"QUIT"):
                response='221 Bye\r\n';
            elif request.upper().startswith(b"RSET"):
                response='250 Ok\r\n';                
            elif request.upper().startswith(b"HELO") or request.upper().startswith(b"EHLO"):
                cmd = request.decode("utf-8")
                domain = cmd[5:-2]
                response='250 Helo ' + domain + '\r\n';
            elif request.upper().startswith(b"STARTTLS"):
                response='220 Ready to start TLS\r\n';
            elif request.upper().startswith(b"VRFY"):
                response='252 VRFY forbidden\r\n';
            elif request.upper().startswith(b"EXPN"):
                response='252 EXPN forbidden\r\n';                
            elif request.upper().startswith(b"MAIL FROM:"):
                cmd = request.decode("utf-8")
                address = cmd[10:-2]
                response='250 Sender ' + address + ' OK\r\n';
            elif request.upper().startswith(b"RCPT TO:"):
                cmd = request.decode("utf-8")
                address = cmd[8:-2]
                response='250 Recipient ' + address + ' OK\r\n';
            elif request.lower().startswith(b"data"):
                data = True
                response='354 Ok Send data ending with <CRLF>.<CRLF>\r\n';
            elif data:
                data = False
                response='250 Ok: queued as ' + str(queueNo()) + '\r\n';
					
            chooseSocket(conn, TLSSSLconn).sendall(response.encode())
                            
            if request.startswith(b"QUIT"):
                raise Exception("Client QUIT")
            elif request.startswith(b"AUTH TLS"):
                TLSSSLconn=context.wrap_socket(conn, server_side=True)
			
            if request.upper().startswith(b"QUIT"):
                raise Exception("Client QUIT")
    except Exception as e:
        logger.info(str(count)+"@"+clientAddr + " -> " + str(e))
        print(str(count)+"@"+clientAddr + " -> " + str(e))
        chooseSocket(conn, TLSSSLconn).close()
    logger.info(str(count)+"@"+clientAddr + " -> disconnected")
    print(str(count)+"@"+clientAddr + " -> disconnected")

#entry point
VERSION = "0.1a"

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
#buat file pem dan key dari https://www.samltool.com/self_signed_certs.php
context.load_cert_chain('certchain.pem', 'private.key')    

ServerSocket = socket.socket()
host = "0.0.0.0"
port = 2525
ThreadCount = 0

#create logger object
logger = logging.getLogger()
logger.setLevel(logging.INFO) 

#create logrotate daily, keep 30 days
handler = TimedRotatingFileHandler('HPOTsmtp.log',
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

logger.info("SMTP HoneyPot " + VERSION + " ready at port " + str(port)) 
print("SMTP HoneyPot " + VERSION + " ready at port " + str(port)) 
ServerSocket.listen(5)

while True:
    Client, address = ServerSocket.accept()
    Client.settimeout(60)
    ThreadCount += 1
    start_new_thread(threaded_client, (Client, address, ThreadCount, logger, context))      
ServerSocket.close()
