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

main()