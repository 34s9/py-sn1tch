try:
    # Attempt to import all required modules. Using try/except statements ensure the program handles missing dependencies.
    # This is crucial to the application so that it can remain being operational.
    import os # Provides cross platform operating system interaction. Which is essential for file handling and directory managament.
    from os.path import isfile, join
    from scapy.all import sniff, wrpcap # Industry standard library for packet capture and wrtiting PCAP files. This was chosen for its reliability.
    import sys # Allows safe programming exit.
except:
    print('[!] Error importing modules.') # Providing immediate feedback to the user, essential for debugging installation issues.
    
class DataAggregation:
    def __init__(self, resetCount):
        # Initializing the data aggregation class
        # Using a class encapsulates related data and methods, imporving modularity and maintainability.
        # Reset count determines the number of packets to capture per sniffing session.
        self.resetCount = resetCount # Integer was chosen because it efficiently represents countable quantities.
        self.amountPassed = 0 # Tracks cumulative packets captured over time. An integer is fast and minimal in memory usage making it the best for this situation.
        self.fileCount = None # Stores the amount of files created. Using an integer. 
        self.packets = [] # Array is an ideal data structure for dynamic and quick appending of packets, this allows for sequential storage and easy indexing.

    def packetCallback(self, packet):
        # Callback function used with scapy.sniff for real-time packet processing.
        # Each captured packet is appended to the packets list for later storage.
        # Lists are optimal for this purpose due to fast append operations.
        self.packets.append(packet)

    def sniffPacket(self):
        # Captures packets from the network.
        # sniff(prn=self.packetCallback, count=self.resetCount) efficiently captures a fixed number of packets.
        # Using a callback function enables immediate processing without storing unnecessary intermediate data.        
        sniff(prn = self.packetCallback, count = self.resetCount)
        self.amountPassed += self.resetCount # Keeps a running total of captured packets, useful for monitoring and reporting.
    
    def writePCAP(self):
        # Writes the accumulated packets to a PCAP file.
        # Using wrpcap ensures compatibility with standard network analysis tools.
        # The fileCount variable provides sequential, non-overlapping filenames, which prevents accidental overwrites.
        wrpcap('logsPCAP/' + str(self.fileCount) + '.pcap', self.packets)

    def loopIterated(self):
        # Increments the fileCount after a successful write operation.
        # This simple integer increment ensures that subsequent files have unique, sequential names.
        self.fileCount += 1

    def resetLogs(self):
        # Placeholder function to delete old PCAP files.
        # Managing disk space is critical for long-running SIEM processes.
        # Future implementation should safely remove files that are no longer needed.
        pass

    def determineFileNumber(self):
        # Determines the next available file number to prevent overwriting existing PCAP files.
        # Using os.listdir provides a reliable way to enumerate existing files.
        # List comprehension with isfile filters only relevant files, avoiding directories.
        try:
            if not os.listdir(directory):
                return 1 # Start numbering at 1 if the directory is empty, therefore avoiding index errors
            else:
                files = [f for f in os.listdir(directory) if isfile(join(directory, f))] # Only including files not directories.
                lastFile = files[-1] # Selecting the last file to determine the latest index.
                lastFile = lastFile[0] # Extracting numeric portion from filename ensuring correct increment.
                self.fileCount = int(lastFile) + 1 # Increasing increment for next available file number.
        except:
            print('[!] Ensure there are only py-sn1tch generated files. Or files that follow the pattern of 1.pcap, 2.pcap etc...')
            try:
                sys.exit() # Safely exiting the program.
            except:
                exit()

if __name__ == '__main__':
    try:
        # Set up directory for storing PCAP files.
        # os.getcwd() ensures that the script works regardless of where it is launched.
        directory = os.getcwd() + '/logsPCAP'
    except:
        print('[!] Ensure you have the logsPCAP folder.')
        try:
            sys.exit() # Exitting if the directory can not be set (aka can not find /logsPCAP)
        except:
            exit()
    
    while True:
        try:
            # Initialize DataAggregation with a fixed packet batch size.
            DA = DataAggregation(resetCount=120)
            DA.determineFileNumber() # Determine file numbering to avoid overwriting.

            DA.sniffPacket() # Capturing packets.
            DA.writePCAP() # Writing captured packets to PCAP.
            DA.loopIterated() # Increment index for next iteration.

        except KeyboardInterrupt:
            print('Stopping dataAggregation...') # Infoming user program has stopped.
            break
        except PermissionError:
            print('Please run the program using sudo.') # Alerting user permission wasnt set.
            break
        except:
            print('Error has occurred') # Error handling to catch program before crashing.
            break
