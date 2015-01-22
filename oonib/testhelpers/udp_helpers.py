
import time

from twisted.internet.protocol import DatagramProtocol

from oonib.sniffer import sniffer

class RawUDPEchoHelper(DatagramProtocol):
    def datagramReceived(self, datagram, address):
        srcaddr, srcport = address
        print "UDP Echo: Received request from {}.".format(address)
        time.sleep(0.1)
        srcaddr, srcport = address
        print "UDP Echo: Sending reply to {}.".format(address)
        self.transport.write(sniffer[0].get_udp(srcaddr, srcport), address)


