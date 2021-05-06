'''
Hendra Soewarno (0119067305)
Honeypot DNS ini tidak disertai pembatasan jumlah thread, sehingga perlu dilakukan
pembatasan pada level firewall.
/sbin/iptables  -A INPUT -p udp --syn --dport 5353 -m connlimit --connlimit-above 50 -j REJECT
DNS mensimulasikan server dns untuk sebagai honeypot yang menarik penyerang
untuk melakukan bruteforce password. Honeypot akan merekam semua userid dan password
yang dicoba penyerang, sehingga menjadi early warning bagi administrator terkait dengan
userid/password yang compromis.
nohup python /path/to/dnssvr.py &
'''
#!/usr/bin/env python3
import json
import time
import datetime  
import socket
import os
import logging
from logging.handlers import TimedRotatingFileHandler
from _thread import *
from pathlib import Path

def parseDNSQ(packet):
    #https://www.ietf.org/rfc/rfc1035.txt
    '''
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    Nb. use byteorder='big'
    '''
    header = packet[0:12]   
    ID = int.from_bytes(header[0:2],byteorder='big')
    #byteorder='big', so byte4 is LSB, and byte3 is MSB
    byte4 = ord(header[3:4]) #LSB
    QR = (byte4 & 0b1)
    Opcode = (byte4 & 0b11110) >> 1
    AA = (byte4 & 0b100000) >> 5
    TC = (byte4 & 0b1000000) >> 6
    RD = (byte4 & 0b10000000) >> 7
    byte3 = ord(header[2:3]) #MSB
    RA = (byte3 & 0b1)
    Z =  (byte3 & 0b1110) >> 1
    RCODE = (byte3 & 0b11110000) >> 4
    QDCOUNT = int.from_bytes(header[4:6],byteorder='big')
    ANCOUNT = int.from_bytes(header[6:8],byteorder='big')
    NSCOUNT = int.from_bytes(header[8:10],byteorder='big')
    ARCOUNT = int.from_bytes(header[10:12],byteorder='big')
    
    hdict = {"ID":hex(ID), "QR": QR , "Opcode": Opcode, "AA":AA, "TC":TC, "RD":RD, "RA":RA, "Z":Z, "RCODE":RCODE, "QDCOUNT": QDCOUNT, "ANCOUNT": ANCOUNT, "NSCOUNT": NSCOUNT, "ARCOUNT": ARCOUNT}   
    
    questions = packet[12:]

    '''
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+        
    '''    
    QNAME = b''
    QTYPE = 0
    QCLASS = 0
    
    qlist = []
    for qi in range(0, QDCOUNT):
        while questions[0:1] != b'\x00':
            nlen = int.from_bytes(questions[0:1], byteorder='big')
            if len(QNAME) > 0:
                QNAME += b'.'
            QNAME += questions[1:1+nlen]
            questions = questions[1+nlen:]        
        
        QTYPE = int.from_bytes(questions[1:3],byteorder='big')
        QCLASS = int.from_bytes(questions[3:5],byteorder='big')
        
        qlist.append({"QNAME":QNAME, "QTYPE":QTYPE, "QCLASS":QCLASS})
        
    dnsq = {"header":hdict, "questions":qlist}
    return dnsq
    
def refuseDNSA(packet):
    #temp = int.from_bytes(packet[2:4],byteorder='big') & 0b0000111111111110 # filter out RCODE
    refused = b'\x80\x85'
    return packet[0:2] + refused +  packet[4:]
   
VERSION = "0.1a"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host = "0.0.0.0"
port = 5353
ThreadCount = 0

#create logger object
logger = logging.getLogger()
logger.setLevel(logging.INFO) 

#create logrotate daily, keep 30 days
handler = TimedRotatingFileHandler('HPOTdns.log',
    when='midnight',
    interval=1,
    backupCount=30)
	
log_format="%(asctime)s %(levelname)s %(threadName)s %(message)s"	
handler.setFormatter(logging.Formatter(log_format))	
logger.addHandler(handler)

try:
    sock.bind((host, port))
except Exception as e:
    print(str(e))

logger.info("DNS HoneyPot " + VERSION + " ready at port " + str(port))  
print("DNS HoneyPot " + VERSION + " ready at port " + str(port))

client = dict() #maintain each client session

while True:
    ## Get the data and the address
    packet, address = sock.recvfrom(512)
    print(address)
    logger.info(address)
    print(parseDNSQ(packet))
    logger.info(parseDNSQ(packet))
    try:
        dnsr = refuseDNSA(packet)
        #print(parseDNSQ(dnsr))
        sock.sendto(dnsr, address)
    except Exception as e:
        print(str(e))
