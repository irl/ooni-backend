
import threading

from scapy.all import *

from oonib.config import config

sniffer = None

class Sniffer(threading.Thread):
    """
    The Sniffer class provides a circular buffer holding packets that have been
    recently seen on the interface selected by the ooni-backend configuration
    file. The number of packets held in the buffer is also selected by the
    ooni-backend configuration file.

    Functions are provided for returning packets from the buffer that match a
    particular flow.

    This class is designed to be used as a singleton and the start_sniffer()
    method is available for creating an instance of the Sniffer class within
    this module in the variable named sniffer.
    """

    def __init__(self):
        threading.Thread.__init__(self)
        self.q = collections.deque(maxlen=config.main.sniffer_queue_size)
        self.setDaemon(True)
        self.start()

    def run(self):
        sniff(filter="tcp port {}".format(config.helpers['http-return-json-headers'].port), iface=config.main.sniffer_interface, prn=lambda x: self.packet_recieved_callback(x))

    def packet_recieved_callback(self, packet):
        """
        This function should not be called directly. It is used as a callback
        for packets sniffed by Scapy.
        """

        self.q.append(packet)
        return "Recieved: {}".format((packet.summary(),))

    def get_udp(self, srcaddr, srcport):
        """
        Returns the packets that have been recieved or sent during a UDP
        conversation initiated by an ooni-probe.
        """

        haystack = list(self.q)
        for packet in haystack:
            if IP in packet:
                if UDP in packet:
                    if packet[IP].src==srcaddr and packet[UDP].sport==srcport:
                        return str(packet)
        return None

    def get_tcp(self, srcaddr, srcport):
        """
        Returns the packets that have been recieved or sent during a TCP
        conversation initiated by an ooni-probe.
        """

        haystack = list(self.q)
        needles = []
        for packet in haystack:
            if IP in packet:
                if TCP in packet:
                    if (packet[IP].src==srcaddr and packet[TCP].sport==srcport ) or (packet[IP].dst==srcaddr and packet[TCP].dport==srcport ):
                        needles.append(packet)
        return needles

def start_sniffer():
    """
    Begin sniffing on the configured interface.
    """

    sniffer = Sniffer()

