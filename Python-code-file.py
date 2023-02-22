import socket 
import struct
import textwrap

#Constants
TAB1 = "\t - "
TAB2 = "\t\t - "
TAB3 = "\t\t\t - "
TAB4 = "\t\t\t\t - "

DATATAB1 = "\t "
DATATAB2 = "\t\t "
DATATAB3 = "\t\t\t " 
DATATAB4 = "\t\t\t\t "


#main function 
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        rawData, address = conn.recvfrom(65536)
        destMac, srcMac, ethProto = webFrame(rawData)
        print("\nFrame:")
        print(TAB1 + "Destination: {}, Source: {}, Protocol: {}".format(destMac,srcMac,ethProto))

        # 8 for ipv4
        if ethProto == 8:
            (vers, headLen, ttl, proto, src, target, data) = ipv4Packet(data)
            print(TAB1 + "IPV4 Packet:")
            print(TAB2 + "Version: {}, Header Length: {}, TTL: {}".format(vers,headLen,ttl))
            print(TAB2 + "Protocol: {}, Source: {}, Target: {}".format(proto,src,target))
            #ICMP
            if proto == 1:
                icmpType, code, checkSum, data = icmpPacket(data)
                print(TAB1 + "ICMP Packet:")
                print(TAB2 + "Type: {}, Code: {}, Checksum: {}, ".format(icmpType,code,checkSum))
                print(TAB2 + "Data: ")
                print(ForMultiLine(DATATAB3, data))
            #TCP
            elif proto == 6:
                (srcPort, destPort, sequ, ackno, flagUrg, flagAck, flagPsh, flagRst, flagSyn, flagFin, data) = tcpSeg(data)
                print(TAB1 + "TCP Segment:")
                print(TAB2 + "Source Port: {}, Destination Port: {}".format(srcPort, destPort))
                print(TAB2 + "Sequence: {}, Acknowledgment: {}".format(sequ, ackno))
                print(TAB2 + "Flags:")
                print(TAB3 + "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flagUrg,flagAck,flagPsh,flagRst,flagSyn,flagFin))
                print(TAB2 + "Data: ")
                print(ForMultiLine(DATATAB3, data))
            #UDP
            elif proto == 17:
                srcPort, destPort, length, data = udpSeg(data) 
                print(TAB1 + "UDP Segment:")
                print(TAB2 + "Source Port: {}, Destination Port: {}, Length: {}".format(srcPort, destPort, length))

            #other protocol 
            else:
                print(TAB1 + "Data:")
                print(ForMultiLine(DATATAB2, data))
        else:
            print("Data:")
            print(ForMultiLine(DATATAB1, data))

#pack unframing 
def webFrame(data):
    destMac, srcMac, proto = struct.unpack("! 6s 6s H", data[:14])
    return getMacAdd(destMac), getMacAdd(srcMac), socket.htons(proto), data[:14]

#returns MAC address 
def getMacAdd(bytesAdd):
    bytesString = map("{:02x}".format, bytesAdd)
    return ":".join(bytesString).upper()

#unpacks IP Packet specifically IPV4
def ipv4Packet(data):
    versHeadLen = data[0]
    vers = versHeadLen >> 4
    headLen = (versHeadLen & 15) * 4 
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return vers, headLen, ttl, proto, ipv4(src), ipv4(target), data[headLen:]

#returns ipv4 address correctly formated (255.255.255.255) 
def ipv4(address):
    return ".".join(map(str, address))

#Unpacks the IMCP packet
def icmpPacket(data):
    icmpType, code, checkSum = struct.unpack("! B B H", data[:4])
    return icmpType, code, checkSum, data[4:]

#Unpacks the TCP segment
def tcpSeg(data):
    (srcPort, destPort, sequ, ackno, offReserFlag) = struct.unpack("! H H L L H", data[:14])
    offset = (offReserFlag >> 12) * 4
    flagUrg = (offReserFlag & 32) >> 5
    flagAck = (offReserFlag & 16) >> 4
    flagPsh = (offReserFlag & 8) >> 3
    flagRst = (offReserFlag & 4) >> 2
    flagSyn = (offReserFlag & 2) >> 1
    flagFin = offReserFlag & 1
    return srcPort, destPort, sequ, ackno, flagUrg, flagAck, flagPsh, flagRst, flagSyn, flagFin, data[offset:]

#Unpack a UDP segment
def udpSeg(data):
    srcPort, destPort, size = struct.unpack("! H H 2x H", data[:8])
    return srcPort, destPort, size, data[8:]

#Formats Multiple line Data
def ForMultiLine(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = "".join(r"\x{:02x}".format(byte) for byte in string)
        if size % 2:
            size -= 1
    return "\n".join([prefix + line for line in textwrap.wrap(string, size)])



main()