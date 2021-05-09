'''
Hendra Soewarno (0119067305)
Honeypot modbus ini tidak disertai pembatasan jumlah thread, sehingga perlu dilakukan
pembatasan pada level firewall.
/sbin/iptables  -A INPUT -p tcp --syn --dport 5502 -m connlimit --connlimit-above 50 -j REJECT
Modbus mensimulasikan server modbus untuk sebagai honeypot yang menarik penyerang
untuk melakukan bruteforce password. Honeypot akan merekam semua userid dan password
yang dicoba penyerang, sehingga menjadi early warning bagi administrator terkait dengan
userid/password yang compromis.
nohup python /path/to/modbus.py &
'''
#!/usr/bin/env python3
import time
import socket
import select
import logging
from logging.handlers import TimedRotatingFileHandler
from _thread import *

def readTCPPDU(conn, length):
    text = b''
    while len(text) < length:
        data = conn.recv(1)
        if not data:
            raise Exception("disconnect from client")
        text += data
    return text

def readMBAPHeader(conn):
    text = b''
    while len(text) < 6:
        data = conn.recv(1)
        if not data:
            raise Exception("disconnect from client")
        text += data
    return text
    
def threaded_client(conn, address, count, logger):
    #print (conn.getsockname())
    serverAddr = conn.getsockname()[0]
    clientAddr = address[0]
    data = ""
    try:
        while True:
            #https://www.bb-elec.com/Learning-Center/All-White-Papers/Modbus/Modbus-TCP-IP-at-a-Glance.aspx            
            #0001 0000 0006 15 03 006B 0003
            '''
            <------------------- MBAP Header ------><---------------------- Modbus TCP/PDU ----------------->
            TransactionId  ProtocolId   Length      UnitId          FunctionCode    DataAddr    NumOfRegister
            2 Bytes         2 Bytes     2 Bytes     1 Byte          1 Byte          2 Bytes     2 Bytes
            '''
            MBAPHeader = readMBAPHeader(conn)
            TransactionId = MBAPHeader[0:2]
            ProtocolId = MBAPHeader[2:4]
            Length = int.from_bytes(MBAPHeader[4:6],byteorder='big')
            print(Length)
            
            MessageTCPPDU = readTCPPDU(conn, Length)
            UnitId = MessageTCPPDU[0:1]
            FunctionCode = int.from_bytes(MessageTCPPDU[1:2],byteorder='big')
            '''
            01 Read discrete output
            02 Read a digital input
            03 Read a analog output
            04 Read a analog input
            05 Write discreate output
            06 Read analog output
            0F Write multiple discrete pins
            10 Write multiple analog outputs            
            '''
            DataAddr = int.from_bytes(MessageTCPPDU[2:4],byteorder='big')
            NumOfRegister = int.from_bytes(MessageTCPPDU[4:6],byteorder='big')
            
            pdict = {"TransactionId":int.from_bytes(TransactionId,byteorder='big'),
                "ProtocolId": int.from_bytes(ProtocolId,byteorder='big'),
                "Length": Length,
                "UnitId": int.from_bytes(UnitId,byteorder='big'),
                "FunctionCode": FunctionCode,
                "DataAddr": DataAddr,
                "NumOfRegister": NumOfRegister}
            print(pdict)
            logger.info(pdict)
            
            #Response with dummy error data
            #https://ipc2u.com/articles/knowledge-base/detailed-description-of-the-modbus-tcp-protocol-with-command-examples/
            '''
            The response will contain the modified Function code, its high-order bit will be 1. 
            
            01	The received function code can not be processed.
            02	The data address specified in the request is not available.
            03	The value contained in the query data field is an invalid value.
            04	An unrecoverable error occurred while the slave attempted to perform the requested action.
            05	The slave has accepted the request and processes it, but it takes a long time. This response prevents the host from generating a timeout error.
            06	The slave is busy processing the command. The master must repeat the message later when the slave is freed.
            07	The slave can not execute the program function specified in the request. This code is returned for an unsuccessful program request using functions with numbers 13 or 14. The master must request diagnostic information or error information from the slave.
            08	The slave detected a parity error when reading the extended memory. The master can repeat the request, but usually in such cases, repairs are required.
            '''
            
            message = UnitId + (FunctionCode | 0b10000000).to_bytes(1, byteorder='big') + b'\x06' # The slave is busy processing the command. The master must repeat the message later when the slave is freed.
            messageLength = len(message)
            errorResponse = TransactionId + ProtocolId + messageLength.to_bytes(2, byteorder='big') + message

            conn.sendall(errorResponse)

    except Exception as e:
        logger.info(str(count)+"@"+clientAddr + " -> " + str(e))
        print(str(count)+"@"+clientAddr + " -> " + str(e))
        conn.close()
        
    #logger.info(str(count)+"@"+clientAddr + " -> disconnected")
    #print(str(count)+"@"+clientAddr + " -> disconnected")

#entry point
VERSION = "0.1a"

ServerSocket = socket.socket()
host = "0.0.0.0"
port = 5502
ThreadCount = 0
			
#create logger object
logger = logging.getLogger()
logger.setLevel(logging.INFO) 

#create logrotate daily, keep 30 days
handler = TimedRotatingFileHandler('HPOTmodbus.log',
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

logger.info("Modbus HoneyPot " + VERSION + " ready at port " + str(port))  
print("Modbus HoneyPot " + VERSION + " ready at port " + str(port)) 
ServerSocket.listen(5)

while True:
    Client, address = ServerSocket.accept()
    Client.settimeout(15)
    ThreadCount += 1
    start_new_thread(threaded_client, (Client, address, ThreadCount, logger))        
ServerSocket.close()
