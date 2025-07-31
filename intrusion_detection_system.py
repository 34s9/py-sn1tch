from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue

# Not designed to be ran by itself, but within main.py.
# Please ensure you run using sudo and -E. 

class DataAggregation:
    def __init__(self):
        self.packetQueue = queue.Queue()
        self.stopCapture = threading.Event()

    def callbackPacket(self, packet):
        if IP in packet and TCP in packet:
            self.packetQueue.put(packet)

    def beginCapture(self, interface = 'eth0'):
        
        def captureThread():
            sniff(iface = interface, prn = self.callbackPacket, store = 0, stop_filter = lambda _: self.stopCapture.is_set())

        self.captureThread = threading.Thread(target = captureThread)
        self.captureThread.start()
        
    def stopCapture(self):
        self.stopCapture.set()
        self.captureThread.join()
