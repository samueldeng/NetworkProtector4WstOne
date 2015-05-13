#!/usr/bin/python

from scapy.all import *
import sys
import getopt
import pwd
import os
import logging
from time import sleep

logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename='ip.log',
                    level=logging.INFO)
count = {}


def process_args(argv):
    username = pwd.getpwuid(os.getuid())[0]
    interface = 'eth0'
    packets = 50
    interval = 2
    threshold = 0.8
    if username != "root":
        print "root permission check failed."
        sys.exit(2)
    try:
        opts, args = getopt.getopt(argv, "hi:I:p:t:", ["interface=", "interval=", "packets=", "threshold="])

        for opt, arg in opts:
            if opt == '-h':
                print 'sudo python NetworkProtector.py -i interface(eth0) -I interval(2s)' \
                      ' -p packets(50) -t threshold(0.5-0.99)'
                sys.exit(1)
            if opt in ("-i", "--interface"):
                interface = arg
            if opt in ("-I", "--interval"):
                interval = int(arg)
            if opt in ("-p", "--packets"):
                packets = int(arg)
            if opt in ("-t", "--threshold"):
                threshold = float(arg)
        return interface, packets, interval, threshold

    except getopt.GetoptError:
        print 'sudo python NetworkProtector.py -i interface(eth0) -I interval(2s) -p packets(50) -t threshold(0.5-0.99)'
        sys.exit(2)


def capture_defender(iface, pkts, thrshld):
    count.clear()
    packets = sniff(count=pkts, filter='ip', iface=iface)

    for pkt in packets:
        try:
            ether_src = pkt[Ether].src
            ether_dst = pkt[Ether].dst

            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            # print ether_src, ether_dst, ip_src, ip_dst

            if not count.has_key((ip_src, ip_dst, ether_src, ether_dst)):
                count[(ip_src, ip_dst, ether_src, ether_dst)] = 0
            count[(ip_src, ip_dst, ether_src, ether_dst)] = count[(ip_src, ip_dst, ether_src, ether_dst)] + 1
        except Exception, e:
            print e

    print "\n##############Scan Result#####################"
    for (k, v) in count.items():
        print k, "---->", v / (pkts * 1.0)
    print "##############Scan Result#####################\n"

    for (k, v) in count.items():
        if v >= pkts * thrshld:
            send_icmp(k[1], k[3], k[0], k[2])


def send_icmp(ip_dst, ether_dst, ip_src, ether_src):
    print "***************************************************"
    print "Detecting a FLOOD from anywhere to IP from: " + ip_src + "  MAC from:" + ether_src
    print "sending a icmp from " + ip_src
    logging.info("ip_src: " + ip_src + "\t" + "mac_src: " + ether_src)
    icmp_packet = Ether(src=ether_dst, dst="ff:ff:ff:ff:ff:ff") / IP(src=str(ip_dst), dst='202.117.15.83') / ICMP()
    # icmp_packet.show()
    sendp(icmp_packet, count=5, iface=iface)
    print "***************************************************\n"


if __name__ == "__main__":
    iface, pkts, intv, thrshld = process_args(sys.argv[1:])
    while True:
        capture_defender(iface, pkts, thrshld)
        sleep(intv)