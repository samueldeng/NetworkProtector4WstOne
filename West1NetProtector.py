import socket
from struct import *
import datetime
import pcapy
import sys

def main(argv):
    # list all devices
    try:
        cap = pcapy.open_live('eth0', 65536, 1, 300)

        # start sniffing packets
        while (1):
            (header, packet) = cap.next()
            print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
            parse_packet(packet)
    except Exception, e:
        print e;


# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


def parse_packet(packet):
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])
    # print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

    if eth_protocol == 8:
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20 + eth_length]
        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        print 'Version : ' + str(version)
        print ' IP Header Length : ' + str(ihl)
        print ' TTL : ' + str(ttl)
        print ' Protocol : ' + str(protocol)
        print ' Source Address : ' + str(s_addr)
        print ' Destination Address : ' + str(d_addr)
        print
        #some other IP packet like IGMP
    else:
        print 'Protocol other than TCP/UDP/ICMP'


if __name__ == "__main__":
    main(sys.argv)