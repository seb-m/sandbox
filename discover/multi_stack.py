from scapy import *


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


if __name__ == '__main__':
    conf.route.ifdel('eth1')
    MultiStack("www.google.com")
    MultiStack("www.yahoo.com")
    MultiStack("www.live.com")
