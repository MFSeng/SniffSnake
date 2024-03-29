#Imported Packages
import socket 
import struct
import textwrap
import datetime
import time
import requests

#Text Spacing for the Log Files
TAB1 = "\t - "
TAB2 = "\t\t - "
TAB3 = "\t\t\t - "
TAB4 = "\t\t\t\t - "

DATATAB1 = "\t "
DATATAB2 = "\t\t "
DATATAB3 = "\t\t\t " 
DATATAB4 = "\t\t\t\t "


#the Main Function. 
def main():
    #Login Function. 
    while True:
        username = input("Enter the admin username: ")
        password = input("Enter the admin password: ")
        if (username == "admin" and password == "Admin1!"):
            break
        else:
            print ("Incorrect Username or Password!")
            continue
    
    print ("You entered the correct credentials")
    #Connection String.
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    #user options
    while True:
        user_option = input("""\nEnter -P for passive sniffer mode 
Enter -15 to see 15 ethernet frames printed tp the screen
Enter -E to close the application
---> """)
        if (user_option == "-P"):
            while True:
                raw_data, address = conn.recvfrom(65536)
                dest_mac, src_mac, eth_proto, data = Ethernet_Unpack(raw_data)
                print("\nFrame:")
                print(TAB1 + "Destination: {}, Source: {}, Protocol: {}".format(dest_mac,src_mac,eth_proto))

                # 8 for ipv4
                if eth_proto == 8:
                    (vers, head_len, ttl, proto, src, target, data) = IPV4_Packet(data)
                    organisation = get_asn_from_ip(target)
                    print(TAB1 + "IPV4 Packet:")
                    print(TAB2 + "Version: {}, Header Length: {}, TTL: {}".format(vers,head_len,ttl))
                    print(TAB2 + "Protocol: {}, Source: {}, Target: {}".format(proto,src,target))
                    if (target == "127.0.0.1" or target == "127.0.0.53" or target =="10.83.81.23"):
                        pass
                    else:
                        org = organisation["org"]
                        print(TAB3 + "Organisation: {}".format(org))

                    #ICMP
                    if proto == 1:
                        icmp_type, code, check_sum, data = IMCP_Packet(data)
                        print(TAB1 + "ICMP Packet:")
                        print(TAB2 + "Type: {}, Code: {}, Checksum: {}, ".format(icmp_type,code,check_sum))
                        print(TAB2 + "Data: ")
                        print(Format_Multiple_Line(DATATAB3, data))
                    #TCP
                    elif proto == 6:
                        (src_port, dest_port, sequ, ackno, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = TCP_Segment(data)
                        print(TAB1 + "TCP Segment:")
                        print(TAB2 + "Source Port: {}, Destination Port: {}".format(src_port, dest_port))
                        print(TAB2 + "Sequence: {}, Acknowledgment: {}".format(sequ, ackno))
                        print(TAB2 + "Flags:")
                        print(TAB3 + "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin))
                        print(TAB2 + "Data: ")
                        print(Format_Multiple_Line(DATATAB3, data))
                    #UDP
                    elif proto == 17:
                        src_port, dest_port, length, data = UDP_Segment(data) 
                        print(TAB1 + "UDP Segment:")
                        print(TAB2 + "Source Port: {}, Destination Port: {}, Length: {}".format(src_port, dest_port, length))

                    if (org == "AS32934 Facebook, Inc."):
                        print ("!!Inserection Detected!!")
                        time_to_stop = time.time() + 60 * 1
                        current_time = str(datetime.datetime.now())
                        current_time = current_time.replace("-", "_")
                        current_time = current_time.replace(":", "-")
                        log_file = open((current_time + ".txt"), "x")

                        while time.time() < time_to_stop:
                            raw_data, address = conn.recvfrom(65536)
                            dest_mac, src_mac, eth_proto, data = Ethernet_Unpack(raw_data)
                            log_file.write("\nFrame:")
                            log_file.write("\n" + TAB1 + "Destination: {}, Source: {}, Protocol: {}".format(dest_mac,src_mac,eth_proto))

                            # 8 for ipv4
                            if eth_proto == 8:
                                (vers, head_len, ttl, proto, src, target, data) = IPV4_Packet(data)
                                organisation = get_asn_from_ip(target)
                                log_file.write("\n" + TAB1 + "IPV4 Packet:")
                                log_file.write("\n" + TAB2 + "Version: {}, Header Length: {}, TTL: {}".format(vers,head_len,ttl))
                                log_file.write("\n" + TAB2 + "Protocol: {}, Source: {}, Target: {}".format(proto,src,target))
                                if (target == "127.0.0.1" or target == "127.0.0.53" or target =="10.83.81.23"):
                                    pass
                                else:
                                    org = organisation["org"]
                                    log_file.write("\n" + TAB3 + "Organisation: {}".format(org))

                                #ICMP
                                if proto == 1:
                                    icmp_type, code, check_sum, data = IMCP_Packet(data)
                                    log_file.write("\n" + TAB1 + "ICMP Packet:")
                                    log_file.write("\n" + TAB2 + "Type: {}, Code: {}, Checksum: {}, ".format(icmp_type,code,check_sum))
                                    log_file.write("\n" + TAB2 + "Data: ")
                                    log_file.write(Format_Multiple_Line(DATATAB3, data))
                                #TCP
                                elif proto == 6:
                                    (src_port, dest_port, sequ, ackno, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = TCP_Segment(data)
                                    log_file.write("\n" + TAB1 + "TCP Segment:")
                                    log_file.write("\n" + TAB2 + "Source Port: {}, Destination Port: {}".format(src_port, dest_port))
                                    log_file.write("\n" + TAB2 + "Sequence: {}, Acknowledgment: {}".format(sequ, ackno))
                                    log_file.write("\n" + TAB2 + "Flags:")
                                    log_file.write("\n" + TAB3 + "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin))
                                    log_file.write("\n" + TAB2 + "Data: ")
                                    log_file.write(Format_Multiple_Line(DATATAB3, data))
                                #UDP
                                elif proto == 17:
                                    src_port, dest_port, length, data = UDP_Segment(data) 
                                    log_file.write("\n" + TAB1 + "UDP Segment:")
                                    log_file.write("\n" + TAB2 + "Source Port: {}, Destination Port: {}, Length: {}".format(src_port, dest_port, length))
                                #other protocol 
                                else:
                                    log_file.write("\n" + TAB1 + "Data:")
                                    log_file.write("\n" + Format_Multiple_Line(DATATAB2, data))
                            else:
                                log_file.write("\n" + "Data:")
                                log_file.write("\n" + Format_Multiple_Line(DATATAB1, data))

                        log_file.close()
                        break
                    else:
                        print(TAB1 + "Data:")
                        print(Format_Multiple_Line(DATATAB2, data))
                else:
                    print("Data:")
                    print(Format_Multiple_Line(DATATAB1, data))

        elif (user_option == "-15"):
            for x in range (15):
                raw_data, address = conn.recvfrom(65536)
                dest_mac, src_mac, eth_proto, data = Ethernet_Unpack(raw_data)
                print("\nFrame:")
                print(TAB1 + "Destination: {}, Source: {}, Protocol: {}".format(dest_mac,src_mac,eth_proto))

                # 8 for ipv4
                if eth_proto == 8:
                    (vers, head_len, ttl, proto, src, target, data) = IPV4_Packet(data)
                    organisation = get_asn_from_ip(target)
                    print(TAB1 + "IPV4 Packet:")
                    print(TAB2 + "Version: {}, Header Length: {}, TTL: {}".format(vers,head_len,ttl))
                    print(TAB2 + "Protocol: {}, Source: {}, Target: {}".format(proto,src,target))
                    if (target == "127.0.0.1" or target == "127.0.0.53" or target =="10.83.81.23"):
                        pass
                    else:
                        org = organisation["org"]
                        print(TAB3 + "Organisation: {}".format(org))

                    #ICMP
                    if proto == 1:
                        icmp_type, code, check_sum, data = IMCP_Packet(data)
                        print(TAB1 + "ICMP Packet:")
                        print(TAB2 + "Type: {}, Code: {}, Checksum: {}, ".format(icmp_type,code,check_sum))
                        print(TAB2 + "Data: ")
                        print(Format_Multiple_Line(DATATAB3, data))
                    #TCP
                    elif proto == 6:
                        (src_port, dest_port, sequ, ackno, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = TCP_Segment(data)
                        print(TAB1 + "TCP Segment:")
                        print(TAB2 + "Source Port: {}, Destination Port: {}".format(src_port, dest_port))
                        print(TAB2 + "Sequence: {}, Acknowledgment: {}".format(sequ, ackno))
                        print(TAB2 + "Flags:")
                        print(TAB3 + "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin))
                        print(TAB2 + "Data: ")
                        print(Format_Multiple_Line(DATATAB3, data))
                    #UDP
                    elif proto == 17:
                        src_port, dest_port, length, data = UDP_Segment(data) 
                        print(TAB1 + "UDP Segment:")
                        print(TAB2 + "Source Port: {}, Destination Port: {}, Length: {}".format(src_port, dest_port, length))
                    #other protocol 
                    else:
                        print(TAB1 + "Data:")
                        print(Format_Multiple_Line(DATATAB2, data))
                else:
                    print("Data:")
                    print(Format_Multiple_Line(DATATAB1, data))

        elif (user_option == "-E"):
            quit()

        else:
            print ("Invalid option Please try again.")
            continue
    

#Functions:
#Unpacks an Ethernet Frame Into the Two MAC Addresses and the Remaining Data.
def Ethernet_Unpack(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return Retrieve_MAC(dest_mac), Retrieve_MAC(src_mac), socket.htons(proto), data[14:] #This line caused issues!!!

#Returns a Correctly Formatted MAC Address. 
def Retrieve_MAC(bytes_add):
    bytes_string = map("{:02x}".format, bytes_add)
    return ":".join(bytes_string).upper()

#Takes the IP Packet and Unpakes it Into Its Relevent Information. 
def IPV4_Packet(data):
    vers_head_len = data[0]
    vers = vers_head_len >> 4
    head_len = (vers_head_len & 15) * 4 
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return vers, head_len, ttl, proto, IPV4(src), IPV4(target), data[head_len:]

#Correctly Formats the IP address to the IPV4 format (255.255.255.255).
def IPV4(address):
    return ".".join(map(str, address))

#Unpacks the IMCP Packet to Identify the Code and Check Sum. 
def IMCP_Packet(data):
    icmp_type, code, check_sum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, check_sum, data[4:]

#Unpacks the TCP Segment to Identify All Its Relevent Information Such as Acknolegment and Flags.
def TCP_Segment(data):
    (src_port, dest_port, sequ, ackno, off_reser_flag) = struct.unpack("! H H L L H", data[:14])
    offset = (off_reser_flag >> 12) * 4
    flag_urg = (off_reser_flag & 32) >> 5
    flag_ack = (off_reser_flag & 16) >> 4
    flag_psh = (off_reser_flag & 8) >> 3
    flag_rst = (off_reser_flag & 4) >> 2
    flag_syn = (off_reser_flag & 2) >> 1
    flag_fin = off_reser_flag & 1
    return src_port, dest_port, sequ, ackno, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Unpacks the UDP Segment to Identify the Ports and Size.
def UDP_Segment(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]

#Takes Multiple Lines of Data and Formats Them Into One Single Line. 
def Format_Multiple_Line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = "".join(r"\x{:02x}".format(byte) for byte in string)
        if size % 2:
            size -= 1
    return "\n".join([prefix + line for line in textwrap.wrap(string, size)])

#Uses an api to detect the organisation of the IP address.
def get_asn_from_ip(ip):
    x = requests.get(f"https://ipinfo.io/{ip}/json?token=94b2b26ca36876")
    y = x.json()
    return y

#Runtime.
main()
