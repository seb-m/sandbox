import os
import sys
from scapy import *


TCPPORTS = [21, 22, 80, 110, 443, 995]
UDPPORTS = [53, 67, 68, 69, 123]


def SynScan(target, sport=None, dport=None):
    if sport is None:
        sport = RandShort()
    if dport is None:
        dport = TCPPORTS

    res, unans = sr(IP(dst=target) /
                    TCP(sport=sport, dport=dport,
                        options=[('Timestamp', (4242, 0))]), retry=-2)

    # affiche tcp flags ou icmp type
    res.make_lined_table(lambda(s, r): (s.dport, s.dst,
                                        r.sprintf("{TCP:%TCP.flags%}"
                                                  "{ICMP:%ICMP.type%}")))

    def popt(p):
        if not p.haslayer(TCP):
            return ''
        for o in p[TCP].options:
            if o[0] == 'Timestamp':
                return str(o[1][0])
        return ''


    # affiche ip id et tcp seq et tcp timestamp
    res.make_lined_table(lambda(s, r): (s.dport, s.dst,
                                        (r.sprintf("%IP.id%, "
                                                   "{TCP:%TCP.seq%}, ") +
                                         popt(r))))


def FTPSPortSynScan(target, dport=None):
    SynScan(target, sport=20, dport=dport)



def UDPScan(target, sport, dport, payload):
    if sport is None:
        sport = RandShort()

    res, unans = sr(IP(dst=target) / UDP(sport=sport, dport=dport) /
                    payload, retry=-2)

    # scan negatifs
    res.show()
    #
    for s, r in res:
        if r.haslayer(ICMP):
            print type(r)
            r.show()
            repr(r)


def DNSScan(target, sport=[53, 67, 68, 69, 123]):
    dns_payload = DNS(qd=DNSQR(qname="www.test.com"))
    dns_dport = [53, 5353]
    UDPScan(target, sport=sport, dport=dns_dport, payload=dns_payload)


def IKEScan(target):
    res, unans = ikescan(target)
    res.show()


def MultiStack(target, dport=80, count=1000, dst='/tmp'):
    res, unans = sr(IP(dst=target) /
                    TCP(sport=[RandShort()] * count,
                        options=[('Timestamp', (4242,0))]),
                    timeout=3)
    prefix = os.path.join(dst, target)

    # plot by ip.id
    g = res.plot(lambda(s, r): r[IP].id,
                 lfilter=lambda(s, r): r.haslayer(IP),
                 title="%s ip id" % target)
    g.hardcopy(filename='%s_ipid.png' % prefix,
               terminal='png')

    # plot by tcp.options.timestamp
    fres = res.filter(lambda(s, r): (r.haslayer(TCP) and
                                     len(r[TCP].options) and
                                     r[TCP].options[-1][0] == 'Timestamp'))
    if fres:
        g = fres.plot(lambda(s, r): r[TCP].options[-1][1][0],
                      title="%s tcp timestamp" % target)
        g.hardcopy(filename='%s_tcptimestamp.png' % prefix,
                   terminal='png')

    # plot by tcp.seq
    g = res.plot(lambda(s,r): r[IP].seq,
                 lfilter=lambda(s, r): r.haslayer(TCP),
                 title="%s tcp seq" % target)
    g.hardcopy(filename='%s_tcpseq.png' % prefix,
               terminal='png')

    print 'plots written to %s*.png' % prefix


def Test():
    #SynScan("82.232.80.143", dport=[80,21,4242])
    #SynScan("dbzteam.org", dport=[80,21,4262,5555])
    #DNSScan("dbzteam.org")
    #IKEScan("dbzteam.org")
    #MultiStack("www.google.com")
    #MultiStack("www.yahoo.com")
    #MultiStack("www.live.com")
    #MultiStack("www.slashdot.org")


if __name__ == '__main__':
    conf.route.ifdel('eth1')
    Test()


# traceroute("82.232.80.143", dport=[21,80,4242], retry=-5)

# packets frag
# res, unans = sr(IP(dst="82.232.80.143", id=RandShort(), ttl=(10, 25), flags="MF")/UDP(sport=RandShort(), dport=53), timeout=125)
# res.make_table(lambda(s, r): (s.dst, s.ttl, r.sprintf("%-15s,IP.src% %ICMP.type% %ICMP.code%")))

# fixme:
# xmas / fin scan
# ntp scan ?
# ack scan ?

# is_promisc
