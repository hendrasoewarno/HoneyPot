'''
Hendra Soewarno (0119067305)
Honeypot TFTP ini tidak disertai pembatasan jumlah thread, sehingga perlu dilakukan
pembatasan pada level firewall.
/sbin/iptables  -A INPUT -p udp --syn --dport 6969 -m connlimit --connlimit-above 50 -j REJECT
TFtpSvr mensimulasikan server ftp untuk sebagai honeypot yang menarik penyerang
untuk melakukan bruteforce password. Honeypot akan merekam semua userid dan password
yang dicoba penyerang, sehingga menjadi early warning bagi administrator terkait dengan
userid/password yang compromis.
nohup python /path/to/tftpsvr.py &
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

class Client:
    def __init__(self, opcode, filename, mode):
        self.opcode = opcode
        self.time = time.time()
        self.mode = mode
        self.currentBlock = 0
        self.ackBlock = -1
        self.closed = False        
        self.errorCode = -1
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S") + "."
        fn=Path(filename.decode("utf-8").replace(".",now,1))
        try:
            if opcode==1: #Read request RRQ
                self.ackBlock = 0            
                self.currentBlock = 0
                self.file0=open(filename, "rb")                
            else:
                self.file0=open(fn, "xb")
                self.file1=open(filename, "wb")
                
        except IOError:
            self.errorCode = 1
            self.closed = True

    def isClosed(self):
        return self.closed
        
    def isTimeOut(self):
        timeout = False
        if time.time() - self.time > 10: #second
            self.file0.close()
            if self.getOpcode() > 1:
                self.file1.close()
            timeout = True
        return timeout
        
    def getOpcode(self):
        return self.opcode
                
    def getErrorCode(self):
        return self.errorCode           


class RRQClient(Client):

    def getNextBlock(self):
        return self.ackBlock+1

    def getNextData(self):
        if self.currentBlock == self.ackBlock:
            self.currentBlock = self.ackBlock + 1 #step next
            self.lastData = self.file0.read(512)
            if len(self.lastData) < 512: #EOF
                self.closed = True
                self.file0.close();                
        return self.lastData
        
    def ackReceived(self, block):
        print("ACK Recieve")
        print(block)
        self.ackBlock=block
            
    def isNextDataReady(self):
        print("IsNExtDataReady")
        print(self.currentBlock)
        print(self.ackBlock)
        return (self.currentBlock == self.ackBlock) #RRQ
        
class WRQClient(Client):
        
    def putDataPacket(self, block, data):
        if block > self.ackBlock:
            self.file0.write(data)
            self.file1.write(data)
            self.currentBlock = block
        else:
            self.closed = True
            self.file0.close()
            self.file1.close()
                        
    def isMustAck(self):
        return (self.ackBlock < self.currentBlock) #WRQ    
        
    def getNextAckBlock(self):
        self.ackBlock=self.currentBlock
        return self.ackBlock        
        
def craftAckPacket(block):
    return b'\0\4' + block.to_bytes(2, byteorder='big')    
    
def craftDataPacket(block, data):
    return b'\0\3' + block.to_bytes(2, byteorder='big') + data
            
def craftErrorPacket(errorCode):
    error = [b'Not defined, see error message (if any).',
        b'File not found.',
        b'Access violation.',
        b'Disk full or allocation exceeded.',
        b'Unknown transfer ID.',
        b'File already exists.',
        b'No such user.'
    ]
    return b'\0\5' + errorCode.to_bytes(2, byteorder='big') + error[errorCode]

def parsePacketAndUpdate(client, address, packet):
    #https://tools.ietf.org/html/rfc1350
    opcode = int.from_bytes(packet[0:2],byteorder='big')
    '''
            pcode operation
            1     Read request (RRQ)
            2     Write request (WRQ)
            3     Data (DATA)
            4     Acknowledgment (ACK)
            5     Error (ERROR)
    '''
    if opcode == 1 or opcode == 2: #RRQ or WRQ
        print(packet)
        logger.info(packet)
        firstZPos = packet[2:].find(b'\0')
        filename =  packet[2:][0:firstZPos]
        secondZPos = packet[2:][0:firstZPos].find(b'\0')
        mode = packet[2+firstZPos+1:secondZPos]
        secondZPos = packet[2+firstZPos:].find(b'\0')
        if opcode==1:
            client[address] = RRQClient(opcode, filename, mode)
        else:
            client[address] = WRQClient(opcode, filename, mode)

    elif opcode == 3: #DATA only posible for WRQ
        block = int.from_bytes(packet[2:4],byteorder='big')
        data = packet[4:]
        client[address].putDataPacket(block,data)
        
    elif opcode == 4: #ACK only posible for RRQ
        print(packet)
        block = int.from_bytes(packet[2:],byteorder='big')
        client[address].ackReceived(block)
        
    else: #ERROR
        print(packet)
        logger.info(packet)
        errorCode=int.from_bytes(packet[2:4],byteorder='big')
        '''
            Value     Meaning
            0         Not defined, see error message (if any).
            1         File not found.
            2         Access violation.
            3         Disk full or allocation exceeded.
            4         Illegal TFTP operation.
            5         Unknown transfer ID.
            6         File already exists.
            7         No such user.
        '''
        errMsg=packet[4:-1]
	
#entry point
VERSION = "0.1a"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host = "0.0.0.0"
port = 6969
ThreadCount = 0

#create logger object
logger = logging.getLogger()
logger.setLevel(logging.INFO) 

#create logrotate daily, keep 30 days
handler = TimedRotatingFileHandler('HPOTtftp.log',
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

logger.info("TFTP HoneyPot " + VERSION + " ready at port " + str(port))  
print("TFTP HoneyPot " + VERSION + " ready at port " + str(port))

client = dict() #maintain each client session

while True:
    ## Get the data and the address
    packet, address = sock.recvfrom(4096)
    print(address)
    logger.info(address)
    parsePacketAndUpdate(client, address, packet)
    
    try:
    
        if address in client:    
            currentClient=client[address]
            if currentClient.getErrorCode() > -1:
                sock.sendto(craftErrorPacket(currentClient.getErrorCode()), address)
        
        for scanAddr in list(client):
            if client[scanAddr].isClosed():
                print("Closed")
                logger.info("Closed")
                client.pop(scanAddr) #remove from client session
            elif client[scanAddr].isTimeOut():
                print("Timeout")
                logger.info("Timeout")
                client.pop(scanAddr) #remove from client session   
                
        if address in client:
            currentClient=client[address]
            if currentClient.getOpcode()==1:
                if currentClient.isNextDataReady():
                    sock.sendto(craftDataPacket(currentClient.getNextBlock(), currentClient.getNextData()), address)        
            elif client[address].getOpcode()==2:
                if currentClient.isMustAck():
                    sock.sendto(craftAckPacket(currentClient.getNextAckBlock()), address)
                    
    except Exception as e:
        print(str(e))
