from scapy.all import sniff, IP, TCP, time
from collections import defaultdict
import threading
import queue
import numpy
from sklearn.ensemble import IsolationForest
import logging
import json
from datetime import datetime

# Not designed to be ran by itself, but within main.py.
# Please ensure you run using sudo and -E. 

class DataAggregation:
    def __init__(self):
        self.packetQueue = queue.Queue()
        self.stopCapture = threading.Event()

        # Implement PCAP/CSV filing here.
        # Write packets to file.

    def callbackPacket(self, packet):
        if IP in packet and TCP in packet:
            self.packetQueue.put(packet)

    def beginCapture(self, interface = 'wlan0'):
        
        def captureThread():
            sniff(iface = interface, prn = self.callbackPacket, store = 0, stop_filter = lambda _: self.stopCapture.is_set())

        self.captureThread = threading.Thread(target = captureThread)
        self.captureThread.start()
        
    def stopCapture(self):
        self.stopCapture.set()
        self.captureThread.join()


class TrafficAnalysis:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flowStats = defaultdict(lambda: {

            'packetCount' : 0,
            'byteCount' : 0,
            'startTime' : None,
            'lastTime' : None

        })
    
    def analyzePacket(self, packet):
        if IP in packet and TCP in packet:

            src = packet[IP].src
            dst = packet[IP].dst
            spt = packet[TCP].sport
            dpt = packet[TCP].dport

            flowKey = (src, dst, spt, dpt)

            stats = self.flowStats[flowKey]
            stats['packetCount'] += 1
            stats['byteCount'] += len(packet)
            currentTime = packet.time

            if not stats['startTime']:
                stats['startTime'] = currentTime
            
            stats['lastTime'] = currentTime

            return self.extractFeatures(packet, stats)
    
    def extractFeatures(self, packet, stats):
        return {
            'packetSize' : len(packet),
            'flowDuration' : stats['lastTime'] - stats['startTime'],
            'packetRate' : stats['packetCount'] / (stats['lastTime'] - stats['startTime']),
            'byteRate' : stats['byteCount'] / (stats['lastTime'] - stats['startTime']),
            'tcpFlags' : packet[TCP].flags,
            'windowSize' : packet[TCP].window
        }

class DetectionEngine:
    def __init__(self):
        self.anomalyDetector = IsolationForest(
            contamination = 0.1,
            random_state = 42
        )

        self.signatureRules = self.loadSignatureRules()
        self.trainingData = []

    def loadSignatureRules(self):
        return {
            'synFlood': {
                'condition': lambda features: (
                    features['tcpFlags'] == 2 and
                    features['packetRate'] > 100
                )
            },
            'portScan': {
                'condition': lambda features: (
                    features['packetSize'] < 100 and
                    features['packetRate'] > 50
                )
            }
        }
    
    def trainAnomalyDetector(self, normalTrafficData):
        self.anomalyDetector.fit(normalTrafficData)
    
    def detectThreats(self, features):
        threats = []

        'Signature Based Detection'
        for ruleName, rule in self.signatureRules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': ruleName,
                    'confidence': 1.0
                })
        
        'Anomaly Based Detection'
        featureVector = numpy.array([[
            features['packetSize'],
            features['packetRate'],
            features['byteRate']
        ]])

        anomalyScore = self.anomalyDetector.score_samples(featureVector)[0]
        if anomalyScore < -0.5:
            threats.append({
                'type': 'anomaly',
                'score': anomalyScore,
                'confidence': min(1.0, abs(anomalyScore))
            })
        
        return threats

class AlertSystem:
    def __init__(self, logFile = 'idsAlerts.log'):
        self.logger = logging.getLogger("idsAlerts")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(logFile)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generateAlert(self, threat, packetInfo):
        alert = {
            'timestamp': datetime.now().isoformat,
            'threatType': threat['type'],
            'sourceIP': packetInfo.get('sourceIP'),
            'destinationIP': packetInfo.get('destinationIP'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }

        self.logger.warning(json.dumps(alert))

        if threat['confidence'] > 0.8:
            self.logger.critical(
                f'High confidence threat detected: {json.dumps(alert)}'
            )

            # Implement additional integration here for notification.
            # E.g Email, Slack, SIEM Here.

class IntrusionDetectionSystem:
    def __init__(self, interface = 'wlan0'):
        self.DataAggregation = DataAggregation()
        self.TrafficAnalysis = TrafficAnalysis()
        self.DetectionEngine = DetectionEngine()
        self.AlertSystem = AlertSystem()

        self.interface = interface
    
    def start(self):
        print(f'Starting IDS on interface {self.interface}')
        self.DataAggregation.beginCapture(self.interface)

        while True:
            try:
                packet = self.DataAggregation.packetQueue.get(timeout = 1)
                features = self.TrafficAnalysis.analyzePacket(packet)

                if features:
                    threats = self.DetectionEngine.detectThreats(features)

                    for threat in threats:
                        packetInfo = {
                            'sourceIP': packet[IP].src,
                            'destinationIP': packet[IP].dst,
                            'sourcePort': packet[TCP].sport,
                            'destinationPort': packet[TCP].dport
                        }
                        
                        self.AlertSystem.generateAlert(threat, packetInfo)
                    
            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print('Stopping IDS...')
                self.DataAggregation.stopCapture()
                break

def testIDS():
    # Creating test packets to simulate scenarios
    testPackets = [
        # Normal Traffic
        IP(src = '192.168.1.1', dst = '192.168.1.2') / TCP(sport = 1234, dport = 80, flags = 'A'),
        IP(src = '192.168.1.3', dst = '192.168.1.4') / TCP(sport = 1235, dport = 443, flags = 'P'),

        # SYN Flood
        IP(src = '10.0.0.1', dst = '192.168.1.2') / TCP(sport = 5678, dport = 80, flags = 'S'),
        IP(src = '10.0.0.2', dst = '192.168.1.2') / TCP(sport = 5679, dport = 80, flags = 'S'),
        IP(src = '10.0.0.3', dst = '192.168.1.2') / TCP(sport = 5680, dport = 80, flags = 'S'),

        # Port Scan
        IP(src = '192.168.1.100', dst = '192.168.1.2') / TCP(sport = 4321, dport = 22, flags = 'S'),
        IP(src = '192.168.1.100', dst = '192.168.1.2') / TCP(sport = 4321, dport = 23, flags = 'S'),
        IP(src = '192.168.1.100', dst = '192.168.1.2') / TCP(sport = 4321, dport = 25, flags = 'S')
    ]

    IDS = IntrusionDetectionSystem()
    IDS.start()

    # Simulating packet processing and threat detection
    print('Starting IDS Test...')
    for i, packet in enumerate(testPackets, 1):
        print(f'\nProcessing packet {i}: {packet.summary()}')
        
        # Analyze packet features
        features = IDS.TrafficAnalysis.analyzePacket(packet)

        if features:
            # Detect threats based on features
            threats = IDS.DetectionEngine.detectThreats(features)

            if threats:
                print(f'Detected Threats: {threats}')
            else:
                print('No Threats detected.')
        
    print('\n IDS test completed.')

if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.start()
