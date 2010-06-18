#!/usr/bin/env python
#
# 02-2008
#
# Reference: see written by Philippe Biondi in Misc Magazine HS1.
#
# Example:
# ./sliced_network_scan.py -i eth0 -t mail.google.com -p 80,443 -c 10 -f /tmp/com.google.mail.log
#
import sys
import logging
from optparse import OptionParser
from scapy import *

# logging
log = logging.getLogger("sliced_net_scan")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(message)s"))
log.addHandler(console_handler)
log.setLevel(20)


def GetIPID(dst, dport, verbose=False):
    ipid = []
    sipid = int(str(RandShort()))
    sport = int(str(RandShort()))

    payload = 'AAAA'
    if dport in (80, 8080, 8000):
        payload = "GET / HTTP/1.1\r\nHost:\r\n\r\n"

    try:
        os.system('iptables -A OUTPUT -p tcp --sport %d --tcp-flags '
                  'RST RST -j DROP' % sport)

        # syn
        syn_pkt = (IP(dst=dst, id=sipid) /
                   TCP(sport=sport, dport=dport, seq=RandShort(),
                       flags='S', options=[('Timestamp', (4242, 0))]))
        filter_sa = ('tcp and src port %d and dst port'
                     ' %d and tcp[13] == 18' % (dport, sport))
        synack_pkt = sr1(syn_pkt, filter=filter_sa, timeout=10, verbose=verbose)

        if synack_pkt is None:
            log.error('SYN-ACK not received')
            return

        next_seq = synack_pkt[TCP].ack
        next_ack = synack_pkt[TCP].seq + 1

        # ack
        ack_pkt =  (IP(dst=dst, id=sipid) /
                    TCP(sport=sport, dport=dport, seq=next_seq,
                        ack=next_ack, flags='A',
                        options=[('Timestamp', (4243, 0))]))
        send(ack_pkt, verbose=verbose)

        # req
        req_pkt = (IP(dst=dst, id=sipid) /
                   TCP(sport=sport, dport=dport, seq=next_seq,
                       ack=next_ack, flags='PA',
                       options=[('Timestamp', (4244, 0))]) /
                   payload)
        send(req_pkt, verbose=verbose)

        def tcp_payload(pkt):
            if pkt.haslayer(Raw):
                print pkt[Raw]
            else:
                pkt.summary()

        def get_ipid(pkt):
            if verbose:
                print pkt.summary()
            ipid.append(pkt[IP].id)

        filter_e = 'tcp and src port %d and dst port %d' % (dport, sport)
        res = sniff(filter=filter_e, prn=get_ipid, timeout=10)

    finally:
        rst_pkt = IP(dst=dst) / TCP(sport=sport, dport=dport, flags='R')
        send(rst_pkt, verbose=verbose)
        os.system('iptables -D OUTPUT -p tcp --sport %d --tcp-flags '
                  'RST RST -j DROP' % sport)

    log.debug(ipid)
    for id in ipid:
        if id:
            return id
    return None


class GraphBuilder(object):
    def __init__(self):
        self.out = ''
        self.stmts = []
        # fixme: prologue/epilogue

    def Emit(self, nodea, nodeb, edgeop='->', attr=''):
        stmt = '%s %s %s %s' % (nodea, edgeop, nodeb, attr)
        self.stmts.append(stmt)

    def __str__(self):
        return '\n'.join(self.stmts)


class SlicedNetworkScan(object):
    def __init__(self, target, dport, sport=None, verbose=False):
        self.target = target
        self.dport = dport
        if sport is None:
            self.sport = RandShort()
        self.hop = None
        self.verbose = verbose
        if verbose:
           log.setLevel(10)
        self.pkts = SndRcvList()

    @staticmethod
    def _GetTS(p):
        if not p.haslayer(TCP):
            return None
        for name, val in p[TCP].options:
            if name == 'Timestamp':
                return val[0]

    class Host(object):
        def __init__(self, pkts):
            s, r = pkts
            ts = SlicedNetworkScan._GetTS(r)
            assert r[IP].id or ts
            self.ipid_range = [r[IP].id]
            if ts is not None:
                self.ts_range = [ts]
            else:
                self.ts_range = []
            self.pkts = [pkts]

        def __iadd__(self, rhs):
            self.ipid_range.extend(rhs.ipid_range)
            self.ts_range.extend(rhs.ts_range)
            self.pkts.extend(rhs.pkts)

        def __eq__(self, rhs):
            if (not self.ts_range and rhs.ts_range) or \
               (self.ts_range and not rhs.ts_range):
                return False
            ipid = self.ipid_range[0]
            if abs(ipid - rhs.ipid_range[0]) > (65535 * 0.005):
                return False
            if self.ts_range and \
                   abs(self.ts_range[0] - rhs.ts_range[0]) > (self.ts_range[0] * 0.01):
                return False
            return True

        def __str__(self):
            out = 'id:%s, ts:%s :\n' % (self.ipid_range, self.ts_range)
            pkts = '\n'.join(['\t%s:%d:%d' % (s.dst, s.dport, s.ttl) \
                              for s, r in self.pkts])
            return out + pkts

    def _OutputAsciiByHost(self):
        hosts = []
        for p in self.pkts:
            try:
                h = SlicedNetworkScan.Host(p)
            except AssertionError:
                continue
            for hh in hosts:
                if hh == h:
                    hh += h
                    break
            else:
                hosts.append(h)
        print ("Display by host (but it's possible that 2+ hosts are"
               " the same host in reality)")
        for host in hosts:
            print host

    def _OutputAsciiByHop(self, func='make_lined_table'):
        def _GetTS(p):
            ts = SlicedNetworkScan._GetTS(p)
            if ts is None:
                return ''
            return '|%d' % ts

        def _GetIPID(p):
            ipid = None
            if not p[IP].id and p.haslayer(TCP) and (p[TCP].flags == 0x12):
                ipid = GetIPID(p[IP].src, p[TCP].sport)
            if ipid is None:
                return ''
            return '(%d)' % ipid

        if self.hop is None:
            return
        current_hop = self.hop
        while True:
            onehop = self.pkts.filter(lambda x: x[0][IP].ttl == current_hop)
            if not onehop:
                break
            print 'Scan hop at distance %d' % current_hop
            table = getattr(onehop, func)
            table(lambda(s, r): (s.dport, s.dst,
                                 r.sprintf("%IP.id%%%s%%s {TCP:%TCP.flags%}"
                                           "{ICMP:%IP.src% %ir,ICMP.type%}") % \
                                 (_GetIPID(r), _GetTS(r))))
            print
            current_hop += 1

    def OutputAsciiToFile(self, filename, mode="ab"):
        log.info('Write results in %s' % filename)
        fo = file(filename, mode)
        stdout = sys.stdout
        sys.stdout = fo

        try:
            self._OutputAsciiByHop()
            #self._OutputAsciiByHop('make_tex_table')
        finally:
            sys.stdout = stdout
            fo.close()

    def OutputAsciiToConsole(self):
        self._OutputAsciiByHop()
        self._OutputAsciiByHost()

    def OutputGraph(self):
        if self.hop is None:
            return
        gb = GraphBuilder()
        # fixme

    def _RecServicesMap(self, target, dport, hop, timeout):
        res, unans = sr(IP(dst=target, ttl=hop) /
                        TCP(sport=self.sport, dport=dport,
                            options=[('Timestamp', (4242, 0))]),
                        retry=-2, timeout=timeout, verbose=self.verbose)
        self.pkts.res.extend(res.res)

        for s, r in res:
            if r.haslayer(ICMP):
                self._RecServicesMap(s[IP].dst, s[IP].dport, hop + 1, timeout)

    def DoServicesMap(self, timeout=125):
        self._RecServicesMap(self.target, self.dport, self.hop, timeout)

    def FindEntryRouter(self):
        res, unans = traceroute(self.target, dport=self.dport,
                                verbose=self.verbose)
        hop = None

        for s, r in res:
            if (hop is not None) and s[IP].ttl >= hop:
                continue
            if r[IP].src == s[IP].dst:
                hop = s[IP].ttl

        if hop is not None:
            log.info("Entry router of %s is at distance %d" % (self.target,
                                                               hop))
            self.hop = hop

    def Run(self, timeout=None):
        self.FindEntryRouter()
        if self.hop is None:
            return
        if timeout is None:
            self.DoServicesMap()
        else:
            self.DoServicesMap(timeout)


def Main():
    usage = ("usage: %prog -t target -p dport1[,dportn] [-i iface]"
             " [-f filename] [-c timeout] [-v]")

    parser = OptionParser(usage=usage)
    parser.add_option("-t", "--target", dest="target", help="Target")
    parser.add_option("-p", "--pdest", dest="pdest",
                      help="List of destination ports.")
    parser.add_option("-i", "--iface", dest="iface",
                      help="Network interface used.")
    parser.add_option("-f", "--filename", dest="filename",
                      help="Optionally dump results to filename")
    parser.add_option("-c", "--timeout", dest="timeout", type="int",
                      help="Timeout value for sent packets")
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true",
                      help="Verbose mode")
    (options, args) = parser.parse_args()

    if not options.target or not options.pdest:
        parser.error("Required argument(s) not provided")

    lpdest = map(lambda p: int(p), options.pdest.split(','))

    if options.iface:
        conf.iface = options.iface

    if options.verbose is None:
        options.verbose = False

    if options.filename:
        fo = file(options.filename, 'wb')
        try:
            fo.write(' '.join(sys.argv) + '\n')
        finally:
            fo.close()

    log.info("Cell descr.: ip.id[(ip.ip)][|tcp.timestamp]"
             " tcp.flags|icmp.src icmp.type")

    sns = SlicedNetworkScan(options.target, lpdest, verbose=options.verbose)
    sns.Run(options.timeout)
    if options.filename:
        fo = file(options.filename, 'wb')
        try:
            fo.write(' '.join(sys.argv) + '\n')
        finally:
            fo.close()
        sns.OutputAsciiToFile(options.filename)
    sns.OutputAsciiToConsole()
    return sns


if __name__ == '__main__':
    conf.route.ifdel('eth1')
    snspl = Main()
    #interact(mydict={'snspl': snspl})
