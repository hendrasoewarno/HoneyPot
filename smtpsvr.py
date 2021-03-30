'''
Hendra Soewarno (0119067305)
Honeypot SMTP ini tidak disertai pembatasan jumlah thread, sehingga perlu dilakukan
pembatasan pada level firewall.
/sbin/iptables  -A INPUT -p tcp --syn --dport 2525 -m connlimit --connlimit-above 50 -j REJECT
SMTPSvr mensimulasikan server pop untuk sebagai honeypot yang menarik penyerang
untuk melakukan bruteforce password. Honeypot akan merekam semua userid dan password
yang dicoba penyerang, sehingga menjadi early warning bagi administrator terkait dengan
userid/password yang compromis.
nohup python /path/to/smtpsvr.py &
'''
#!/usr/bin/env python3
import time
import datetime  
import socket
import os
import logging
import base64
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
    auth = 0

    try:
        while True:
            if not data:
                request=readRequest(conn)
            else:
                request=readBody(conn)
                
            logger.info(request) 
            print(request)
            response='502 Command not implemented\r\n'
            if not data:
                if auth == 1:
                    cmd = request.decode("utf-8")
                    b64username = cmd[0:-2]                   
                    username = base64.b64decode(b64username)
                    logger.info(username)
                    auth = 2
                    response='334 UGFzc3dvcmQ6\r\n';  #base64 Password
                elif auth == 2:
                    cmd = request.decode("utf-8")
                    b64password = cmd[0:-2]                   
                    password = base64.b64decode(b64password)
                    logger.info(password)                
                    if password== b'password':
                        auth = 0
                        response='235 Authentication successful\r\n';
                    else:
                        auth = 0
                        response='535 Authentication failure\r\n';
                elif request.lower().startswith(b"auth login"):
                    auth = 1
                    response='334 VXNlcm5hbWU6\r\n'; #base64 Username
                elif request.lower().startswith(b"auth plain"):
                    cmd = request.decode("utf-8")
                    b64usernamepassword = cmd[11:-2]                   
                    plain = base64.b64decode(b64usernamepassword)
                    logger.info(plain)
                    if plain.endswith(b'password'):
                        response='235 Authentication successful\r\n';
                    else:
                        response='535 Authentication failure\r\n';                    
                elif request.lower().startswith(b"quit"):
                    response='221 Bye\r\n';
                elif request.lower().startswith(b"helo") or request.lower().startswith(b"ehlo"):
                    response='250-8BITMIME\r\n250-PIPELINING\r\n250-SIZE 31457280\r\n250-AUTH PLAIN LOGIN\r\n250 AUTH=PLAIN LOGIN\r\n';
                elif request.lower().startswith(b"mail from:"):
                    cmd = request.decode("utf-8")
                    address = cmd[10:-2]
                    response='250 Sender ' + address + ' OK\r\n';
                elif request.lower().startswith(b"rcpt to:"):
                    cmd = request.decode("utf-8")
                    address = cmd[8:-2]
                    response='250 Recipient ' + address + ' OK\r\n';
                elif request.lower().startswith(b"data"):
                    data = True
                    response='354 Ok Send data ending with <CRLF>.<CRLF>\r\n';
            else:
                step = 0
                response='250 Ok: queued as ' + str(queueNo()) + '\r\n';
					
            conn.sendall(response.encode())
			
            if request.startswith(b"quit"):
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
    start_new_thread(threaded_client, (Client, address, ThreadCount, logger))        
ServerSocket.close()
