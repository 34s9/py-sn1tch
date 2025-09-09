import os
from os.path import isfile, join
from scapy.all import sniff, wrpcap
import sys

class DataAggregation:
    def __init__(self, resetCount):
        self.resetCount = resetCount
        self.amountPassed = 0
        self.fileCount = None
        self.packets = []

    def packetCallback(self, packet):
        self.packets.append(packet)

    def sniffPacket(self):
        sniff(prn = self.packetCallback, count = self.resetCount)
        self.amountPassed += self.resetCount
    
    def writePCAP(self):
        wrpcap('logsPCAP/' + str(self.fileCount) + '.pcap', self.packets)

    def loopIterated(self):
        self.fileCount += 1

    def resetLogs(self):
        pass
        # Insert code to delete logsPCAP files here.

    def determineFileNumber(self):
        try:
            if not os.listdir(directory):
                return 1
            else:
                files = [f for f in os.listdir(directory) if isfile(join(directory, f))]
                lastFile = files[-1]
                lastFile = lastFile[0]
                self.fileCount = int(lastFile) + 1
        except:
            print('[!] Ensure there are only py-sn1tch generated files. Or files that follow the pattern of 1.pcap, 2.pcap etc...')
            try:
                sys.exit()
            except:
                exit()

if __name__ == '__main__':
    try:    
        directory = os.getcwd() + '/logsPCAP'
    except:
        print('[!] Ensure you have the logsPCAP folder.')
        try:
            sys.exit()
        except:
            exit()
    
    while True:
        try:
            # Insert threading here.
            DA = DataAggregation(resetCount=120)
            DA.determineFileNumber()

            DA.sniffPacket()
            DA.writePCAP()
            DA.loopIterated()

            # Insert code to update tkinter display...

        except KeyboardInterrupt:
            print('Stopping dataAggregation...')
            break
        except PermissionError:
            print('Please run the program using sudo.')
            break
        except:
            print('Error has occurred')
            break
