import socket 
import struct
import textwrap

#main function 
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        rawData, address = conn.recvfrom(65536)
        destMac, srcMac, ethProto = webFrame(rawData)
        print('\nFrame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(destMac,srcMac,ethProto))

#pack unframing 
def webFrame(data):
    destMac, srcMac, proto = struct.unpack('! 6s 6s H', data[:14])
    return getMacAdd(destMac), getMacAdd(srcMac), socket.htons(proto), data[:14]

#returns MAC address 
def getMacAdd(bytesAdd):
    bytesString = map('{:02x}'.format, bytesAdd)
    return ':'.join(bytesString).upper()

#unpacks IP Packet specifically IPV4
def ipv4Packet(data):
    versHeadLen = data[0]
    vers = versHeadLen >> 4
    headLen = (versHeadLen & 15) * 4 
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return vers, headLen, ttl, proto, ipv4(src), ipv4(target), data[headLen:]

#returns ipv4 address correctly formated (255.255.255.255) 
def ipv4(address):
    return '.'.join(map(str, address))


main()