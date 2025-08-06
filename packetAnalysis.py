
"""
HEY! Before you continue, this engine was created by a different developer (Github repo linked below),
I only made some minor changes to the engine code, and fully wrote out the documentation.

TODO: documentation, integration into main.py

Developers Github Repo Link: https://github.com/ivan-si/pcap-analyzer
"""

#!/usr/bin/env python3

# pcap_analyzer.py
# Analyzes PCAP files or live network traffic for anomalous patterns,
# suspicious connections, and integrates with Azure services.

import logging
import argparse
import os
import time
from datetime import datetime
import threading # For periodic flow analysis in live mode
import signal # For graceful shutdown

# Attempt to import Scapy and its layers
try:
    from scapy.all import rdpcap, IP, TCP, UDP, sniff
    from scapy.error import Scapy_Exception
    try:
        from scapy.layers.http import HTTPRequest, HTTPResponse, HTTP
        SCAPY_HTTP_AVAILABLE = True
    except ImportError:
        SCAPY_HTTP_AVAILABLE = False
except ImportError:
    print("Critical Error: Scapy is not installed. Please install it: pip install scapy")
    print("For optional detailed HTTP analysis, you might also need: pip install scapy[http]")
    exit(1)

# Azure SDKs
AZURE_SDK_AVAILABLE = False

class PcapAnalyzer:
    """
    Analyzes PCAP files or live traffic for network anomalies and integrates with Azure.
    """
    def __init__(self, monitor_conn_str=None, storage_conn_str=None, blacklist_table_name="blacklistips"):
        self.malicious_ips = set()
        self.local_blacklist_file = "ipBlacklist.txt"
        self.flows = {}  # flow_key -> {details}
        self.packet_count = 0 # For live mode packet counting

        self.long_connection_threshold_seconds = 3600
        self.unusual_port_min_threshold = 1024
        self.flow_timeout_seconds = 300 # For live mode: consider a flow inactive after 5 mins

        self.logger = self._setup_basic_logging()
        self.azure_monitor_conn_str = monitor_conn_str
        self.azure_storage_conn_str = storage_conn_str
        self.azure_blacklist_table_name = blacklist_table_name
        self.tracer = None
        self.table_client = None
        self.live_capture_stop_event = threading.Event() # For stopping live capture thread
        self._load_malicious_ips()

    def _setup_basic_logging(self):
        logger = logging.getLogger(self.__class__.__name__)
        logger.setLevel(logging.INFO)
        if not logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def _load_malicious_ips_from_local_file(self):
        initial_count = len(self.malicious_ips)
        try:
            with open(self.local_blacklist_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        self.malicious_ips.add(ip)
            loaded_count = len(self.malicious_ips) - initial_count
            if loaded_count > 0:
                 self.logger.info(f"Loaded {loaded_count} IPs from local file: {self.local_blacklist_file}")
        except FileNotFoundError:
            self.logger.warning(f"Local blacklist file '{self.local_blacklist_file}' not found. Creating an empty one.")
            try:
                with open(self.local_blacklist_file, 'w') as f:
                    f.write("# Add one IP address or domain per line.\n")
            except IOError as e:
                self.logger.error(f"Could not create local blacklist file '{self.local_blacklist_file}': {e}")
        except Exception as e:
            self.logger.error(f"Error loading local malicious IPs: {e}")

    def _load_malicious_ips_from_azure(self):
        if not self.table_client:
            return

    def _log_anomaly_to_azure(self, anomaly_name: str, attributes: dict):
        if self.tracer:
            try:
                with self.tracer.start_as_current_span(anomaly_name) as span:
                    for key, value in attributes.items():
                        span.set_attribute(key, str(value))
                self.logger.debug(f"Logged to Azure Monitor: {anomaly_name} - {attributes}")
            except Exception as e:
                self.logger.error(f"Error logging to Azure Monitor: {e}")

    def _load_malicious_ips(self):
        self._load_malicious_ips_from_local_file()
        self._load_malicious_ips_from_azure()
        if self.malicious_ips:
            self.logger.info(f"Total {len(self.malicious_ips)} unique malicious IPs/domains loaded.")
        else:
            self.logger.warning("No malicious IPs/domains loaded. Blacklist is empty.")

    def _update_flow_stats(self, pkt):
        if IP not in pkt:
            return False # Indicate that this packet doesn't contribute to an IP flow

        try:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto_num = pkt[IP].proto
            pkt_len = len(pkt)
            pkt_time = float(pkt.time) if hasattr(pkt, 'time') else time.time()

            sport, dport = 0, 0
            protocol_name = "Other"

            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                protocol_name = "TCP"
            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                protocol_name = "UDP"

            flow_key = (src_ip, sport, dst_ip, dport, proto_num)

            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    'start_time': pkt_time,
                    'last_seen': pkt_time,
                    'packets': 1,
                    'bytes': pkt_len,
                    'protocol_name': protocol_name,
                    'flagged_anomalies': set(),
                    'src_ip': src_ip, 'sport': sport, # Store for easier access later
                    'dst_ip': dst_ip, 'dport': dport
                }
            else:
                self.flows[flow_key]['last_seen'] = pkt_time
                self.flows[flow_key]['packets'] += 1
                self.flows[flow_key]['bytes'] += pkt_len
            return True # Successfully updated/created flow
        except Exception as e:
            self.logger.error(f"Error updating flow stats for packet: {e} - {pkt.summary() if hasattr(pkt, 'summary') else 'Packet summary unavailable'}")
            return False

    def _check_malicious_ip(self, pkt_num, pkt_time, src_ip, dst_ip, flow_key):
        anomaly_type = None
        malicious_ip_involved = None
        
        if src_ip in self.malicious_ips:
            anomaly_type = "MaliciousSourceCommunication"
            malicious_ip_involved = src_ip
        elif dst_ip in self.malicious_ips:
            anomaly_type = "MaliciousDestinationCommunication"
            malicious_ip_involved = dst_ip
        
        if anomaly_type and anomaly_type not in self.flows[flow_key]['flagged_anomalies']:
            msg = (f"Packet {pkt_num}: {anomaly_type} - Flow {src_ip} -> {dst_ip}. "
                   f"Malicious IP: {malicious_ip_involved}")
            self.logger.warning(msg)
            attributes = {
                "packet_num": pkt_num, "timestamp": datetime.fromtimestamp(pkt_time).isoformat(),
                "src_ip": src_ip, "dst_ip": dst_ip, "malicious_entity": malicious_ip_involved
            }
            self._log_anomaly_to_azure(anomaly_type, attributes)
            self.flows[flow_key]['flagged_anomalies'].add(anomaly_type)

    def _check_unusual_port(self, pkt_num, pkt_time, proto_name, port, src_ip, dst_ip, direction, flow_key):
        common_ports = {
            20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 113, 123, 135, 137, 138, 139, 143, 161, 162,
            389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 990, 993, 995,
            1080, 1194, 1433, 1521, 1701, 1723, 1812, 1813,
            2049, 3306, 3389, 5060, 5061, 5432, 5900, 8080, 8443
        }
        anomaly_type = "UnusualPortUsage"
        if port > self.unusual_port_min_threshold and port not in common_ports:
            if anomaly_type not in self.flows[flow_key]['flagged_anomalies']:
                msg = (f"Packet {pkt_num}: {anomaly_type} - {proto_name} {direction} port {port} "
                       f"for flow {src_ip} -> {dst_ip}.")
                self.logger.info(msg)
                attributes = {
                    "packet_num": pkt_num, "timestamp": datetime.fromtimestamp(pkt_time).isoformat(),
                    "protocol": proto_name, "port": port, "src_ip": src_ip, "dst_ip": dst_ip, "direction": direction
                }
                self._log_anomaly_to_azure(anomaly_type, attributes)
                self.flows[flow_key]['flagged_anomalies'].add(anomaly_type)

    def _analyze_http_traffic(self, pkt_num, pkt_time, pkt, src_ip, dst_ip, dport, flow_key):
        anomaly_type_port = "HTTPOnNonStandardPort"
        anomaly_type_proto = "NonHTTPOnStandardHTTPPort"

        if SCAPY_HTTP_AVAILABLE and (pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse) or pkt.haslayer(HTTP)):
            if dport not in {80, 8080, 443}:
                if anomaly_type_port not in self.flows[flow_key]['flagged_anomalies']:
                    msg = (f"Packet {pkt_num}: {anomaly_type_port} - HTTP traffic on port {dport} "
                           f"for flow {src_ip} -> {dst_ip}.")
                    self.logger.warning(msg)
                    attributes = {"packet_num": pkt_num, "timestamp": datetime.fromtimestamp(pkt_time).isoformat(),
                                  "src_ip": src_ip, "dst_ip": dst_ip, "port": dport}
                    self._log_anomaly_to_azure(anomaly_type_port, attributes)
                    self.flows[flow_key]['flagged_anomalies'].add(anomaly_type_port)
        elif dport == 80:
            is_http_layer_present = SCAPY_HTTP_AVAILABLE and \
                                    (pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse) or pkt.haslayer(HTTP))
            if TCP in pkt and pkt[TCP].payload and not is_http_layer_present:
                if anomaly_type_proto not in self.flows[flow_key]['flagged_anomalies']:
                    msg = (f"Packet {pkt_num}: {anomaly_type_proto} - Non-HTTP TCP traffic on port 80 "
                           f"for flow {src_ip} -> {dst_ip}.")
                    self.logger.warning(msg)
                    attributes = {"packet_num": pkt_num, "timestamp": datetime.fromtimestamp(pkt_time).isoformat(),
                                  "src_ip": src_ip, "dst_ip": dst_ip}
                    self._log_anomaly_to_azure(anomaly_type_proto, attributes)
                    self.flows[flow_key]['flagged_anomalies'].add(anomaly_type_proto)

    def process_pcap_file(self, pcap_file_path):
        """Processes a PCAP file (original functionality)."""
        self.logger.info(f"Starting PCAP file processing for: {pcap_file_path}")
        if not os.path.exists(pcap_file_path):
            self.logger.error(f"PCAP file not found: {pcap_file_path}")
            return

        try:
            packets = rdpcap(pcap_file_path)
        except Scapy_Exception as e:
            self.logger.error(f"Scapy error reading PCAP file '{pcap_file_path}': {e}")
            return
        except Exception as e: # Catch other potential errors
            self.logger.error(f"Generic error reading PCAP file '{pcap_file_path}': {e}")
            return
        
        self.logger.info(f"Successfully loaded {len(packets)} packets from '{pcap_file_path}'.")
        self.packet_count = 0 # Reset for file mode

        for i, pkt in enumerate(packets):
            self.packet_count = i + 1
            if self.packet_count % 1000 == 0:
                self.logger.info(f"Processing packet {self.packet_count}/{len(packets)}...")
            
            if not self._update_flow_stats(pkt): continue # Skip non-IP

            try:
                # Re-extract packet details for analysis, using flow_key to access stored flow data
                src_ip_pkt = pkt[IP].src; dst_ip_pkt = pkt[IP].dst; proto_num_pkt = pkt[IP].proto
                sport_pkt, dport_pkt = 0,0
                if TCP in pkt: sport_pkt, dport_pkt = pkt[TCP].sport, pkt[TCP].dport
                elif UDP in pkt: sport_pkt, dport_pkt = pkt[UDP].sport, pkt[UDP].dport
                flow_key = (src_ip_pkt, sport_pkt, dst_ip_pkt, dport_pkt, proto_num_pkt)

                if flow_key not in self.flows: 
                    self.logger.error(f"Flow key {flow_key} missing for packet {self.packet_count} in file mode. This indicates an issue in _update_flow_stats or logic.")
                    continue 

                flow_data = self.flows[flow_key]
                src_ip, dst_ip = flow_data['src_ip'], flow_data['dst_ip']
                sport, dport = flow_data['sport'], flow_data['dport']
                protocol_name = flow_data['protocol_name']
                # Use packet's own timestamp if available, crucial for PCAP analysis
                pkt_time = float(pkt.time) if hasattr(pkt, 'time') and pkt.time is not None else time.time()


                self._check_malicious_ip(self.packet_count, pkt_time, src_ip, dst_ip, flow_key)
                if protocol_name == "TCP":
                    self._check_unusual_port(self.packet_count, pkt_time, "TCP", sport, src_ip, dst_ip, "source", flow_key)
                    self._check_unusual_port(self.packet_count, pkt_time, "TCP", dport, src_ip, dst_ip, "destination", flow_key)
                    self._analyze_http_traffic(self.packet_count, pkt_time, pkt, src_ip, dst_ip, dport, flow_key)
                elif protocol_name == "UDP":
                    self._check_unusual_port(self.packet_count, pkt_time, "UDP", sport, src_ip, dst_ip, "source", flow_key)
                    self._check_unusual_port(self.packet_count, pkt_time, "UDP", dport, src_ip, dst_ip, "destination", flow_key)
            except Exception as e:
                 self.logger.error(f"Error analyzing packet {self.packet_count} from file: {e} - {pkt.summary() if hasattr(pkt, 'summary') else 'Packet summary unavailable'}")


        self._analyze_flows_post_file_capture() # Specific for file mode
        self.logger.info(f"Finished processing PCAP file: {pcap_file_path}")


    def _analyze_flows_post_file_capture(self):
        """Analyzes collected flows after processing a whole PCAP file."""
        self.logger.info("\n--- Post-File-Capture Flow Analysis ---")
        if not self.flows:
            self.logger.info("No flows were captured or analyzed from the file.")
            return

        for flow_key, data in self.flows.items():
            # For file analysis, duration is always based on actual packet timestamps
            duration = data['last_seen'] - data['start_time']
            anomaly_type = "LongLivedConnection"

            if duration > self.long_connection_threshold_seconds:
                if anomaly_type not in data['flagged_anomalies']:
                    msg = (f"{anomaly_type}: {data['protocol_name']} flow {data['src_ip']}:{data['sport']} -> {data['dst_ip']}:{data['dport']} "
                           f"Duration: {duration:.2f}s, Packets: {data['packets']}, Bytes: {data['bytes']}")
                    self.logger.warning(msg)
                    attributes = {
                        "src_ip": data['src_ip'], "sport": data['sport'], "dst_ip": data['dst_ip'], "dport": data['dport'],
                        "protocol": data['protocol_name'], "duration_seconds": f"{duration:.2f}",
                        "packets_count": data['packets'], "bytes_transferred": data['bytes']
                    }
                    self._log_anomaly_to_azure(anomaly_type, attributes)
                    data['flagged_anomalies'].add(anomaly_type) 
        
        self.logger.info(f"Analyzed {len(self.flows)} flows post-file-capture.")
        self.flows.clear() 

# Global instance for signal handling
analyzer_instance = None

def signal_handler(sig, frame):
    global analyzer_instance
    # Use print as logger might be affected during shutdown or if it's the source of issues
    print(f"\nSignal {sig} received, shutting down gracefully...") 
    if analyzer_instance:
        analyzer_instance.live_capture_stop_event.set() 
    # Further cleanup or OTel shutdown is handled in main's finally block

def main():
    global analyzer_instance
    parser = argparse.ArgumentParser(
        description="PCAP Anomalous Traffic Analyzer (Live & File Mode).",
        formatter_class=argparse.RawTextHelpFormatter
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--pcap-file", help="Path to the PCAP file to analyze.")
    
    args = parser.parse_args()

    # Initialize analyzer_instance here so it's available for signal_handler early
    # and logger is configured before any major operations.
    analyzer_instance = PcapAnalyzer(
        #monitor_conn_str=args.monitor_conn_str,
        #storage_conn_str=args.storage_conn_str,
        #blacklist_table_name=args.blacklist_table
    )

    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)  # Handles Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler) # Handles termination signal (e.g., from `kill`)

    try:
        if args.pcap_file:
            analyzer_instance.process_pcap_file(args.pcap_file)
    except KeyboardInterrupt: # Explicitly catch KeyboardInterrupt here if Ctrl+C is not fully handled by signal
        analyzer_instance.logger.info("KeyboardInterrupt caught in main. Shutting down...")
        if analyzer_instance:
             analyzer_instance.live_capture_stop_event.set() # Ensure stop event is set
    except Exception as e: 
        if analyzer_instance and analyzer_instance.logger:
            analyzer_instance.logger.critical(f"A critical error occurred in main execution: {e}", exc_info=True)
        else: # Logger might not be initialized if error is very early
            print(f"A critical error occurred in main execution before logger was ready: {e}")


if __name__ == "__main__":
    # Basic check if Scapy's core components seem available
    # (Scapy_Exception would be defined if `from scapy.error import Scapy_Exception` succeeded)
    if 'Scapy_Exception' not in globals(): 
        # This message is printed at the top if initial Scapy import fails.
        # This is a fallback, but the exit(1) at the top should prevent reaching here.
        print("Exiting: Scapy core components failed to import. Please check installation.")
    else:
        main()
