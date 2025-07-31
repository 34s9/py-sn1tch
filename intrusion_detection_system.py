from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue
import numpy
from sklearn.ensemble import IsolationForest

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

class IntrusionDetectionSystem:
    def __init__(self):
        pass
