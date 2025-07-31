from scapy.all import sniff, wrpcap

class dataAggregation:
    def __init__(self, resetCount):
        self.resetCount = resetCount
        self.amountPassed = 0
        self.fileCount = 1
        self.packets = []

    def packetCallback(self, packet):
        self.packets.append(packet)

    def sniffPacket(self):
        sniff(prn = self.packetCallback, count = self.resetCount)
        self.amountPassed += self.resetCount
    
    def writePCAP(self):
        wrpcap('logsPCAP/' + str(self.fileCount), self.packets)

    def resetLogs(self):
        pass
        # Insert code to delete logsPCAP files here.

if __name__ == '__main__':
    dataAggregation = dataAggregation(10)
    dataAggregation.sniffPacket()
    dataAggregation.writePCAP()
    print('Ending')
