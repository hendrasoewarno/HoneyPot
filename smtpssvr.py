'''
Hendra Soewarno (0119067305)
Honeypot SMTPs ini tidak disertai pembatasan jumlah thread, sehingga perlu dilakukan
pembatasan pada level firewall.
/sbin/iptables  -A INPUT -p tcp --syn --dport 5587 -m connlimit --connlimit-above 50 -j REJECT
SMTPSvr mensimulasikan server smtp untuk sebagai honeypot yang menarik penyerang
untuk melakukan bruteforce password. Honeypot akan merekam semua userid dan password
yang dicoba penyerang, sehingga menjadi early warning bagi administrator terkait dengan
userid/password yang compromis.
nohup python /path/to/smtpssvr.py &
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

def threaded_client(conn, address, count, logger):
    #print (conn.getsockname())
    serverAddr = conn.getsockname()[0]
    clientAddr = address[0]
    logger.info(str(count)+"@"+clientAddr + " -> connected to " + serverAddr) 
    print(str(count)+"@"+clientAddr + " -> connected to " + serverAddr)
    time.sleep(2) # Sleep for 2 seconds
    strwelcome = b"220 SMTP Server Ready\r\n"
    conn.sendall(strwelcome)
    data = False

    try:
        while True:
            if not data:
                request=readRequest(conn)
            else:
                request=readBody(conn)
            logger.info(request) 
            print(request)
            response='502 Command not implemented\r\n'
            if request.upper().startswith(b"QUIT"):
                response='221 Bye\r\n';
            elif request.upper().startswith(b"HELO") or request.upper().startswith(b"EHLO"):
                response='250 Helo\r\n';
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
					
            conn.sendall(response.encode())
			
            if request.upper().startswith(b"QUIT"):
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
port = 5587
ThreadCount = 0

#create logger object
logger = logging.getLogger()
logger.setLevel(logging.INFO) 

#create logrotate daily, keep 30 days
handler = TimedRotatingFileHandler('HPOTsmtps.log',
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

SecureServerSocket=context.wrap_socket(ServerSocket, server_side=True)

while True:
    Client, address = SecureServerSocket.accept()
    Client.settimeout(15)
    ThreadCount += 1
    start_new_thread(threaded_client, (Client, address, ThreadCount, logger))        
ServerSocket.close()
