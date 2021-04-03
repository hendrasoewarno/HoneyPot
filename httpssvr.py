'''
Hendra Soewarno (0119067305)
Gunakan Python3.6 keatas
Honeypot FTP ini tidak disertai pembatasan jumlah thread, sehingga perlu dilakukan
pembatasan pada level firewall.
/sbin/iptables  -A INPUT -p tcp --syn --dport 4443 -m connlimit --connlimit-above 50 -j REJECT
HttpSvr mensimulasikan server telnet untuk sebagai honeypot yang menarik penyerang
untuk melakukan bruteforce password. Honeypot akan merekam semua userid dan password
yang dicoba penyerang, sehingga menjadi early warning bagi administrator terkait dengan
userid/password yang compromis.
nohup python /path/to/httpssvr.py &
'''
#!/usr/bin/env python3
import time
import datetime  
import socket
import ssl
import select
import logging
from logging.handlers import TimedRotatingFileHandler
from _thread import *

def readRequest(conn):
    text = b""
    while not text.endswith(b"\r\n\r\n"):
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
    try:
        response = 'HTTP/1.0 404 NOT FOUND\n\n<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>'
        while True:       
            request=readRequest(conn)
            body=b""
            print(request)
            if request.startswith(b"GET /"):
                if request.startswith(b"GET / "):
                    # Get the content of index.html
                    fin = open('index.html')
                    content = fin.read()
                    fin.close()

                    # Send HTTP response
                    now = datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
                    response = 'HTTP/1.0 200 OK\nDate: ' + now + '\nServer: Apache\nContent-Type: text/html;charset=UTF-8\nContent-Length:' + str(len(content)) +'\n\n' + content
            elif request.startswith(b"POST / "):
                body=readBody(conn)
                print(body)                
                response = 'HTTP/1.0 401 Unauthorized\n\n<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"><html><head><title>401 Unauthorized</title></head><body><h1>Error 401 - Unauthorized</h1><p>Access is denied, invalid username or password.</p></body></html>'			

            logger.info(request.decode("UTF-8").replace("\r\n\r\n","\n")+body.decode("UTF-8"))
            conn.sendall(response.encode())
            raise Exception("response succeed")			
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
port = 4443
ThreadCount = 0

#create logger object
logger = logging.getLogger()
logger.setLevel(logging.INFO) 

#create logrotate daily, keep 30 days
handler = TimedRotatingFileHandler('HPOThttps.log',
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

logger.info("HTTPS HoneyPot " + VERSION + " ready at port " + str(port)) 
print("HTTPS HoneyPot " + VERSION + " ready at port " + str(port)) 
ServerSocket.listen(5)

SecureServerSocket=context.wrap_socket(ServerSocket, server_side=True)

while True:
    Client, address = SecureServerSocket.accept()
    Client.settimeout(15)
    ThreadCount += 1
    start_new_thread(threaded_client, (Client, address, ThreadCount, logger))        
ServerSocket.close()