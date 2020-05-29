#!/usr/bin/env python

import os, sys, socket, struct, select, time, signal, numpy
 
if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time
 
#----------------------------------------------------------------------------#

# ICMP parameters
ICMP_ECHOREPLY  =    0 # Echo reply (per RFC792 and RFC1739)
ICMP_ECHO       =    8 # Echo request (per RFC792 and RFC1739)
ICMP_MAX_RECV   = 2048 # Max size of incoming buffer
 
MAX_SLEEP = 1000
 
class MyStats:
    thisIP   = "0.0.0.0"
    pktsSent = 0
    pktsRcvd = 0
    minTime  = 999999999
    maxTime  = 0
    totTime  = 0 #sum of each ping delays 
    fracLoss = 1.0
    delayList = []
    hostName = ''
    startTime, endTime = 0,0
 
myStats = MyStats # Used globally
 
#----------------------------------------------------------------------------#

def checksum(source_string):
    
    countTo = (int(len(source_string)/2))*2
    sum = 0
    count = 0
 
    # Handle bytes by decoding as short ints
    loByte = 0
    hiByte = 0
    while count < countTo:
        if (sys.byteorder == "little"):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        sum = sum + (hiByte * 256 + loByte)
        count += 2
 
    # Handle last byte if applicable (odd-number of bytes)
    if countTo < len(source_string): # Check for odd length
        loByte = source_string[len(source_string)-1]
        sum += loByte
 
    sum &= 0xffffffff # Truncate sum to 32 bits 
    sum = (sum >> 16) + (sum & 0xffff)    # Add high 16 bits to low 16 bits
    sum += (sum >> 16)                    # Add carry from above (if any)
    answer = ~sum & 0xffff              # Invert and truncate to 16 bits
    answer = socket.htons(answer)
 
    return answer
 
#----------------------------------------------------------------------------#

def do_one(destIP, timeout, mySeqNumber, numDataBytes):
    """
    Returns either the delay (in ms) or None on timeout.
    """
    global myStats
 
    delay = None #delay means roundTrip time
 
    try: 
        mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except socket.error as e:
        print("failed. (socket error: '%s')" % e.args[1])
        raise # raise the original error
 
    my_ID = os.getpid() & 0xFFFF
 
    sentTime = send_one_ping(mySocket, destIP, my_ID, mySeqNumber, numDataBytes)
    if sentTime == None:
        mySocket.close()
        return delay
 
    myStats.pktsSent += 1;
 
    recvTime, dataSize, iphSrcIP, icmpSeqNumber, iphTTL = receive_one_ping(mySocket, my_ID, timeout)
 
    mySocket.close()
 
    if recvTime:
        delay = (recvTime-sentTime)*1000; myStats.delayList.append(delay)
        print("%d bytes from %s: icmp_seq=%d ttl=%d time=%0.3f ms" % (dataSize, socket.inet_ntoa(struct.pack("!I", iphSrcIP)), icmpSeqNumber, iphTTL, delay))
        myStats.pktsRcvd += 1;
        myStats.totTime += delay
        if myStats.minTime > delay:
            myStats.minTime = delay
        if myStats.maxTime < delay:
            myStats.maxTime = delay
    else:
        delay = None
        print("Request timed out.")
 
    return delay
 
#----------------------------------------------------------------------------#
def send_one_ping(mySocket, destIP, myID, mySeqNumber, numDataBytes):
    """
    Send one ping to the given >destIP<.
    """
    destIP  =  socket.gethostbyname(destIP)
 
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
 
    # Make a dummy heder with a 0 checksum.
    header = struct.pack(
        "!BBHHH", ICMP_ECHO, 0, myChecksum, myID, mySeqNumber
    )
 
    padBytes = []
    startVal = 0x42
    for i in range(startVal, startVal + (numDataBytes)):
        padBytes += [(i & 0xff)]  # Keep chars in the 0-255 range
    data = bytes(padBytes)
 
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data) # Checksum is in network order
    header = struct.pack("!BBHHH", ICMP_ECHO, 0, myChecksum, myID, mySeqNumber)
    packet = header + data
    sendTime = time.time()
    try:
        mySocket.sendto(packet, (destIP, 1)) # Port number is irrelevant for ICMP
    except socket.error as e:
        print("General failure (%s)" % (e.args[1]))
        return
 
    return sendTime

#----------------------------------------------------------------------------#
def receive_one_ping(mySocket, myID, timeout):
    """
    Receive the ping from the socket. Timeout = in ms
    """
    timeLeft = timeout/1000
 
    while True: # Loop while waiting for packet or timeout
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
            return None, 0, 0, 0, 0
 
        timeReceived = time.time()
 
        recPacket, addr = mySocket.recvfrom(ICMP_MAX_RECV)
 
        ipHeader = recPacket[:20]
        iphVersion, iphTypeOfSvc, iphLength, \
        iphID, iphFlags, iphTTL, iphProtocol, \
        iphChecksum, iphSrcIP, iphDestIP = struct.unpack(
            "!BBHHHBBHII", ipHeader
        )
 
        icmpHeader = recPacket[20:28]
        icmpType, icmpCode, icmpChecksum, \
        icmpPacketID, icmpSeqNumber = struct.unpack(
            "!BBHHH", icmpHeader
        )
 
        if icmpPacketID == myID: # Our packet
            dataSize = len(recPacket) - 28
            return timeReceived, dataSize, iphSrcIP, icmpSeqNumber, iphTTL
 
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return None, 0, 0, 0, 0
 
#----------------------------------------------------------------------------#
def dump_stats():
    """
    Show stats when pings are done
    """
    global myStats
 
    print("\n---- %s PYTHON PING Statistics ----" % (myStats.hostName))
 
    if myStats.pktsSent > 0:
        myStats.fracLoss = (myStats.pktsSent - myStats.pktsRcvd)/myStats.pktsSent
 
    print("%d packets transmitted, %d packets received, %0.1f%% packet loss, time %dms" % (myStats.pktsSent, myStats.pktsRcvd, 100.0 * myStats.fracLoss, (myStats.endTime-myStats.startTime)+(myStats.pktsSent-1)*1000)) #(myStats.pktsSent-1)*1000 is the total of waiting/sleep/lag time btw each ping.
 
    if myStats.pktsRcvd > 0:
        print("Round-Trip Times:\nMinimum = %0.3f ms\tMaximum = %0.3f ms\nAverage = %0.3f ms\tStandard Deviation = %0.3f ms" %
(myStats.minTime, myStats.maxTime, myStats.totTime/myStats.pktsRcvd, numpy.std(myStats.delayList)))
    return
 
#----------------------------------------------------------------------------#

def ping(hostname, timeout = 1000, numDataBytes = 56):
    """
    Ping to >destIP< with the given >timeout< and display
    the result.
    """
    global myStats
    myStats = MyStats() # Reset the stats
    mySeqNumber = 1 # Starting value
 
    try:
        destIP = socket.gethostbyname(hostname) # DNS lookup 
        print("\nPYTHON PING %s (%s) with %d data bytes:" % (hostname, destIP, numDataBytes))
    except socket.gaierror as e:
        print("\nPYTHON PING: Unknown host: %s (%s)" % (hostname, e.args[1]))
        print()
        return
    
    myStats.hostName = hostname
    myStats.thisIP = destIP
 
    try:
        myStats.startTime = time.time()
        while True:
            delay = do_one(destIP, timeout, mySeqNumber, numDataBytes)
 
            if delay == None:
                delay = 0
 
            mySeqNumber += 1
    
            if (MAX_SLEEP > delay):
                time.sleep((MAX_SLEEP - delay)/1000)
    except KeyboardInterrupt:
        myStats.endTime = time.time()
        dump_stats()
 
#----------------------------------------------------------------------------#

if __name__ == '__main__':
 
    hostname = input("Enter name/IP address of the host: ")
    ping(hostname)
 
#----------------------------------------------------------------------------#
