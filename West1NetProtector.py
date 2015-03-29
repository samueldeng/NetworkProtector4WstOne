from scapy.all import *
from time import sleep

IFACE = 'eth0'
CAPPKT = 20
SLEEP_INTER = 3  # count for seconds.
count = {}


def sendICMP(ip_dst, ether_dst, ip_src, ether_src):
    print "***************************************************"
    print "Detecting a FLOOD from anywhere to IP from: " + ip_src + "  MAC from:" + ether_src
    print "sending a icmp from " + ip_src
    icmpFuckU = Ether(src=ether_dst, dst="ff:ff:ff:ff:ff:ff") / IP(src=str(ip_dst), dst='202.117.15.83') / ICMP()
    # icmpFuckU.show()
    sendp(icmpFuckU, count=5, iface=IFACE)
    print "Fuck You Attacker!"
    print "***************************************************"
    print "***************************************************"
    print "\n"


def main():
    count.clear()
    packets = sniff(count=CAPPKT, filter='ip', iface=IFACE)


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

    print "\n"
    print "##############Scan Result#####################"
    for (k, v) in count.items():
        print k, "---->", v / (CAPPKT * 1.0)
    print "##############Scan Result#####################"
    print "\n"
    for (k, v) in count.items():
        if v >= CAPPKT * 0.7:
            sendICMP(k[1], k[3], k[0], k[2])


while (True):
    main()
    sleep(SLEEP_INTER)
