from scapy.all import *
from time import sleep

IFACE = 'eth0'
CAPPKT=100
SLEEP_INTER = 5 #count for seconds.
count = {}

def sendICMP(ip_src):
    print "***************************************************"
    print "***************************************************"
    print "Detecting a FLOOD from anywhere to " + ip_src
    print "sending a icmp from " + ip_src
    icmpFuckU = IP(src=str(ip_src),dst='202.117.15.83')/ICMP()
    send(icmpFuckU, iface=IFACE)
    print "Fuck You Attacker!"
    print "***************************************************"
    print "***************************************************"
    count.clear()


def main():
    packets = sniff(count=CAPPKT, filter='ip', iface=IFACE)

    try:
        for pkt in packets:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            if not count.has_key((ip_src, ip_dst)):
                count[(ip_src, ip_dst)] = 0
            count[(ip_src, ip_dst)] = count[(ip_src, ip_dst)] + 1

        for (k,v) in count.items():
            print k,v
            if v > CAPPKT * 0.8:
                sendICMP(k[1])
    except Exception,e:
        pass

while(True):
    main()
    sleep(SLEEP_INTER)