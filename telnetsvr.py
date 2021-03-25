'''
Hendra Soewarno (0119067305)

Honeypot telnet ini tidak disertai pembatasan jumlah thread, sehingga perlu dilakukan
pembatasan pada level firewall.

/sbin/iptables  -A INPUT -p tcp --syn --dport 2323 -m connlimit --connlimit-above 50 -j REJECT

TelnetSvr mensimulasikan server telnet untuk sebagai honeypot yang menarik penyerang
untuk melakukan bruteforce password. Honeypot akan merekam semua userid dan password
yang dicoba penyerang, sehingga menjadi early warning bagi administrator terkait dengan
userid/password yang compromis.

nohup python /path/to/telnetsvr.py &
'''
#!/usr/bin/env python3
import time
import socket
import select
import logging
from logging.handlers import TimedRotatingFileHandler
from _thread import *

def readln(conn):
    text = b""
    skip = 0
    while not text.endswith(b"\r\n"):
        data = conn.recv(1)
        if not data:
            raise Exception("disconnect from client")
        if data == b"\xff": #IAC Character
            skip = 2 #iqnore next two character after IAC Character
        elif skip == 0:
            text += data
        else:
            skip -= 1		
        #print(text)
    return text[0:-2]

def threaded_client(conn, address, count, logger):
    #print (conn.getsockname())
    serverAddr = conn.getsockname()[0]
    clientAddr = address[0]
    logger.info(str(count)+"@"+clientAddr + " -> connected to " + serverAddr) 
    print(str(count)+"@"+clientAddr + " -> connected to " + serverAddr)   
    time.sleep(2) # Sleep for 2 seconds
    strwelcome = b"Ubuntu 18.04.1 LTS server\r\n"
    strlogin = b"login as: "
    strpassword = b"password: "
    strfake = b"\r\nAccess denied\r\n"
	#ANSI/VT100 Terminal Control Escape Sequences
    conn.sendall(b"\033[H") #move cursor top left
    conn.sendall(b"\033[2J") #clear screen
    #conn.sendall(b"\033[?25l"); #hide cursor
    conn.sendall(strwelcome)
    userid = ""
    password = ""
    data = ""
    step = 0
    try:
        while True:            
            if step == 0:
                conn.sendall(strlogin)				
            else:
                conn.sendall(userid)
                conn.sendall(b"@")
                conn.sendall(str.encode(serverAddr))
                conn.sendall(b"'s ")
                conn.sendall(strpassword)
                conn.sendall(b"\xff\xfb\x01") #RFC 857 IAC WONT ECHO                         
            data = readln(conn)
            if step == 0:
                userid=data
            else:
                password=data
                logger.info("login " + userid.decode("utf-8") + " -> " + password.decode("utf-8"))
                time.sleep(1) # Sleep for 1 seconds
                conn.sendall(b"\xff\xfc\x01") #RFC 857 IAC WILL ECHO
                conn.sendall(strfake)
            step = step + 1				
            if step > 6:
                raise Exception("reached 6 attempt(s)")
                break
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
port = 2323
ThreadCount = 0
			
#create logger object
logger = logging.getLogger()
logger.setLevel(logging.INFO) 

#create logrotate daily, keep 30 days
handler = TimedRotatingFileHandler('HPOTtelnet.log',
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

logger.info("Telnet HoneyPot " + VERSION + " ready...") 
print("Telnet HoneyPot " + VERSION + " ready...")
ServerSocket.listen(5)

while True:
    Client, address = ServerSocket.accept()
    Client.settimeout(15)
    ThreadCount += 1
    start_new_thread(threaded_client, (Client, address, ThreadCount, logger))        
ServerSocket.close()