
"""
HEY! Before you continue, this engine was created by a different developer (Github repo linked below),
I only made some minor changes to the engine code, and fully wrote out the documentation.

TODO: Remove Azure_SDK integration, documentation.

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
try:
    #from opentelemetry import trace
    #from opentelemetry.sdk.trace import TracerProvider
    #from opentelemetry.sdk.trace.export import BatchSpanProcessor
    #from azure.monitor.opentelemetry.exporter import AzureMonitorTraceExporter
    #from azure.data.tables import TableServiceClient
    #from azure.core.exceptions import AzureError
    pass
except ImportError:
    AZURE_SDK_AVAILABLE = False

class PcapAnalyzer:
    """
    Analyzes PCAP files or live traffic for network anomalies and integrates with Azure.
    """
    def __init__(self, monitor_conn_str=None, storage_conn_str=None, blacklist_table_name="blacklistips"):
        self.malicious_ips = set()
        self.local_blacklist_file = "malicious_ips.txt"
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

        if AZURE_SDK_AVAILABLE:
            self._initialize_azure_monitor()
            self._initialize_azure_table_storage()
        else:
            self.logger.warning("Azure SDKs not fully installed. Azure integration will be disabled. "
                                "Install with: pip install azure-monitor-opentelemetry-exporter opentelemetry-api opentelemetry-sdk azure-data-tables")
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

    def _initialize_azure_monitor(self):
        if self.azure_monitor_conn_str:
            try:
                provider = TracerProvider()
                trace.set_tracer_provider(provider)
                exporter = AzureMonitorTraceExporter(connection_string=self.azure_monitor_conn_str)
                provider.add_span_processor(BatchSpanProcessor(exporter))
                self.tracer = trace.get_tracer(__name__)
                self.logger.info("Azure Monitor (OpenTelemetry) configured successfully.")
            except Exception as e:
                self.logger.error(f"Failed to initialize Azure Monitor: {e}. Azure Monitor logging disabled.")
                self.tracer = None
        else:
            self.logger.info("Azure Monitor connection string not provided. Azure Monitor logging disabled.")

    def _initialize_azure_table_storage(self):
        if self.azure_storage_conn_str and self.azure_blacklist_table_name:
            try:
                table_service_client = TableServiceClient.from_connection_string(self.azure_storage_conn_str)
                self.table_client = table_service_client.get_table_client(self.azure_blacklist_table_name)
                self.logger.info(f"Connected to Azure Table Storage: '{self.azure_blacklist_table_name}'.")
            except AzureError as e:
                self.logger.error(f"Azure Table Storage connection error: {e}. Azure Table integration disabled.")
                self.table_client = None
            except Exception as e:
                self.logger.error(f"Failed to connect to Azure Table Storage: {e}. Azure Table integration disabled.")
                self.table_client = None
        else:
            self.logger.info("Azure Storage connection string or table name not provided. Azure Table Storage integration disabled.")

    def _log_anomaly_to_azure(self, anomaly_name: str, attributes: dict):
        if self.tracer:
            try:
                with self.tracer.start_as_current_span(anomaly_name) as span:
                    for key, value in attributes.items():
                        span.set_attribute(key, str(value))
                self.logger.debug(f"Logged to Azure Monitor: {anomaly_name} - {attributes}")
            except Exception as e:
                self.logger.error(f"Error logging to Azure Monitor: {e}")

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
        initial_count = len(self.malicious_ips)
        try:
            entities = self.table_client.list_entities()
            azure_ips_loaded = 0
            for entity in entities:
                ip_or_domain = entity.get('RowKey') or entity.get('IPAddress') or entity.get('DomainName')
                if ip_or_domain:
                    self.malicious_ips.add(str(ip_or_domain))
                    azure_ips_loaded +=1
            if azure_ips_loaded > 0:
                self.logger.info(f"Loaded/updated {azure_ips_loaded} IPs/domains from Azure Table Storage '{self.azure_blacklist_table_name}'.")
        except AzureError as e:
            self.logger.error(f"Azure error loading malicious IPs from Table Storage: {e}")
        except Exception as e:
            self.logger.error(f"Error loading malicious IPs/domains from Azure Table Storage: {e}")

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

    def analyze_packet_callback(self, pkt):
        """Callback for Scapy's sniff function. Analyzes a single live packet."""
        self.packet_count += 1
        if self.packet_count % 100 == 0: # Log progress for live capture
             self.logger.info(f"Processed {self.packet_count} live packets...")
        
        # _update_flow_stats returns False if packet is not IP or error occurs
        if not self._update_flow_stats(pkt):
            return # Skip non-IP packets or packets causing flow update errors

        # Retrieve details from the flow entry after update
        # This requires flow_key to be correctly derived as in _update_flow_stats
        try:
            src_ip_pkt = pkt[IP].src
            dst_ip_pkt = pkt[IP].dst
            proto_num_pkt = pkt[IP].proto
            sport_pkt, dport_pkt = 0,0
            if TCP in pkt: sport_pkt, dport_pkt = pkt[TCP].sport, pkt[TCP].dport
            elif UDP in pkt: sport_pkt, dport_pkt = pkt[UDP].sport, pkt[UDP].dport
            
            flow_key = (src_ip_pkt, sport_pkt, dst_ip_pkt, dport_pkt, proto_num_pkt)

            if flow_key not in self.flows:
                self.logger.error(f"Flow key {flow_key} not found for packet {self.packet_count} after _update_flow_stats. This should not happen.")
                return

            flow_data = self.flows[flow_key]
            src_ip = flow_data['src_ip']
            dst_ip = flow_data['dst_ip']
            sport = flow_data['sport']
            dport = flow_data['dport']
            protocol_name = flow_data['protocol_name']
            pkt_time = float(pkt.time) if hasattr(pkt, 'time') else time.time()

            self._check_malicious_ip(self.packet_count, pkt_time, src_ip, dst_ip, flow_key)

            if protocol_name == "TCP":
                self._check_unusual_port(self.packet_count, pkt_time, "TCP", sport, src_ip, dst_ip, "source", flow_key)
                self._check_unusual_port(self.packet_count, pkt_time, "TCP", dport, src_ip, dst_ip, "destination", flow_key)
                self._analyze_http_traffic(self.packet_count, pkt_time, pkt, src_ip, dst_ip, dport, flow_key)
            elif protocol_name == "UDP":
                self._check_unusual_port(self.packet_count, pkt_time, "UDP", sport, src_ip, dst_ip, "source", flow_key)
                self._check_unusual_port(self.packet_count, pkt_time, "UDP", dport, src_ip, dst_ip, "destination", flow_key)
        except Exception as e:
            self.logger.error(f"Error analyzing live packet {self.packet_count}: {e} - {pkt.summary() if hasattr(pkt, 'summary') else 'Packet summary unavailable'}")


    def _periodic_flow_analysis(self):
        """Periodically analyzes flows for inactivity and long-lived connections in live mode."""
        while not self.live_capture_stop_event.is_set():
            self.live_capture_stop_event.wait(self.flow_timeout_seconds / 2) # Check more frequently than timeout
            if self.live_capture_stop_event.is_set(): break

            current_time = time.time()
            flows_to_delete = []
            # Iterate over a copy of keys if modifying dict during iteration
            for flow_key, data in list(self.flows.items()):
                duration = current_time - data['start_time']
                last_seen_ago = current_time - data['last_seen']
                
                anomaly_type_long = "LongLivedConnection"
                # Check for long-lived connections that are still active or recently timed out
                if duration > self.long_connection_threshold_seconds and \
                   anomaly_type_long not in data['flagged_anomalies']:
                    msg = (f"{anomaly_type_long}: {data['protocol_name']} flow {data['src_ip']}:{data['sport']} -> {data['dst_ip']}:{data['dport']} "
                           f"has been active for {duration:.2f}s (Packets: {data['packets']}, Bytes: {data['bytes']}).")
                    self.logger.warning(msg)
                    attributes = {
                        "src_ip": data['src_ip'], "sport": data['sport'], "dst_ip": data['dst_ip'], "dport": data['dport'],
                        "protocol": data['protocol_name'], "current_duration_seconds": f"{duration:.2f}",
                        "packets_count": data['packets'], "bytes_transferred": data['bytes']
                    }
                    self._log_anomaly_to_azure(anomaly_type_long, attributes)
                    data['flagged_anomalies'].add(anomaly_type_long) # Mark as logged for this flow

                # If flow is inactive (timed out)
                if last_seen_ago > self.flow_timeout_seconds:
                    self.logger.info(f"Flow Timeout: {data['protocol_name']} flow {data['src_ip']}:{data['sport']} -> {data['dst_ip']}:{data['dport']} "
                                     f"inactive for {last_seen_ago:.2f}s. Total duration: {(data['last_seen'] - data['start_time']):.2f}s. Removing from active flows.")
                    # Final check for long-lived before removing, if not already flagged
                    final_duration = data['last_seen'] - data['start_time']
                    if final_duration > self.long_connection_threshold_seconds and \
                       anomaly_type_long not in data['flagged_anomalies']:
                        msg = (f"Final {anomaly_type_long}: {data['protocol_name']} flow {data['src_ip']}:{data['sport']} -> {data['dst_ip']}:{data['dport']} "
                               f"ended. Duration: {final_duration:.2f}s, Packets: {data['packets']}, Bytes: {data['bytes']}")
                        self.logger.warning(msg)
                        attributes = {
                            "src_ip": data['src_ip'], "sport": data['sport'], "dst_ip": data['dst_ip'], "dport": data['dport'],
                            "protocol": data['protocol_name'], "final_duration_seconds": f"{final_duration:.2f}",
                            "packets_count": data['packets'], "bytes_transferred": data['bytes'], "status": "timed_out"
                        }
                        self._log_anomaly_to_azure(anomaly_type_long, attributes)
                        # No need to add to flagged_anomalies as it's being removed.
                    flows_to_delete.append(flow_key)

            for key in flows_to_delete:
                if key in self.flows:
                    del self.flows[key]
            if flows_to_delete:
                self.logger.info(f"Removed {len(flows_to_delete)} timed-out flows. Active flows: {len(self.flows)}")


    def start_live_capture(self, interface_name, bpf_filter=""):
        """Starts live packet capture on the specified interface."""
        # Original line that reportedly caused SyntaxError for the user on Python 3.9:
        # self.logger.info(f"Starting live capture on interface: {interface_name} with filter: '{bpf_filter if bpf_filter else "None"}'")
        
        # Modified approach: Pre-calculate the filter string part for logging
        # This is to simplify the expression within the f-string, which might help if there's a subtle parsing issue.
        _filter_display_for_log = bpf_filter if bpf_filter else "None"
        self.logger.info(f"Starting live capture on interface: {interface_name} with filter: '{_filter_display_for_log}'")
        self.logger.info("Press Ctrl+C to stop capturing.")

        # Start periodic flow analysis in a separate thread
        flow_analyzer_thread = threading.Thread(target=self._periodic_flow_analysis, daemon=True)
        flow_analyzer_thread.start()

        try:
            # store=0 means packets are not stored in memory by sniff, only processed by prn
            # stop_filter can be used for more complex stopping conditions
            sniff(iface=interface_name, prn=self.analyze_packet_callback, store=0, stop_filter=lambda p: self.live_capture_stop_event.is_set(), filter=bpf_filter)
        except Scapy_Exception as e:
            self.logger.error(f"Scapy error during live capture on interface '{interface_name}': {e}")
            self.logger.error("Ensure you have necessary permissions (e.g., run as root/admin) and the interface name is correct.")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during live capture: {e}")
        finally:
            self.logger.info("Live capture stopping...")
            self.live_capture_stop_event.set() # Signal periodic analyzer to stop
            if flow_analyzer_thread.is_alive():
                flow_analyzer_thread.join(timeout=5) # Wait for thread to finish
            self.logger.info(f"Live capture finished. Total packets processed: {self.packet_count}")
            self._final_flow_cleanup_and_analysis() # Analyze any remaining flows


    def _final_flow_cleanup_and_analysis(self):
        """Analyzes any remaining flows when capture stops (e.g., Ctrl+C)."""
        self.logger.info("\n--- Final Flow Analysis (Live Mode Shutdown) ---")
        # current_time = time.time() # Not strictly needed here as we use flow's last_seen
        if not self.flows:
            self.logger.info("No active flows remaining at shutdown.")
            return

        for flow_key, data in list(self.flows.items()): # Iterate over a copy
            duration = data['last_seen'] - data['start_time'] # Use last_seen for final duration
            anomaly_type = "LongLivedConnection"
            
            if duration > self.long_connection_threshold_seconds and anomaly_type not in data['flagged_anomalies']:
                msg = (f"Shutdown - {anomaly_type}: {data['protocol_name']} flow {data['src_ip']}:{data['sport']} -> {data['dst_ip']}:{data['dport']} "
                       f"Duration: {duration:.2f}s, Packets: {data['packets']}, Bytes: {data['bytes']}")
                self.logger.warning(msg)
                attributes = {
                    "src_ip": data['src_ip'], "sport": data['sport'], "dst_ip": data['dst_ip'], "dport": data['dport'],
                    "protocol": data['protocol_name'], "final_duration_seconds": f"{duration:.2f}",
                    "packets_count": data['packets'], "bytes_transferred": data['bytes'], "status": "shutdown_cleanup"
                }
                self._log_anomaly_to_azure(anomaly_type, attributes)
        self.logger.info(f"Cleaned up and analyzed {len(self.flows)} remaining flows at shutdown.")
        self.flows.clear()


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

    def shutdown_otel(self):
        """Shuts down the OpenTelemetry tracer provider to flush data."""
        if self.tracer and hasattr(trace.get_tracer_provider(), 'shutdown'):
             self.logger.info("Shutting down OpenTelemetry tracer provider to flush data...")
             try:
                 trace.get_tracer_provider().shutdown()
                 self.logger.info("OpenTelemetry tracer provider shut down successfully.")
             except Exception as e:
                 self.logger.error(f"Error shutting down OpenTelemetry tracer provider: {e}")

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
    mode_group.add_argument("--interface", help="Network interface name for live capture (e.g., eth0, en0). Requires root/admin privileges.")

    parser.add_argument("--bpf-filter", help="BPF filter string for live capture (e.g., 'tcp port 80').", default="")
    
    azure_group = parser.add_argument_group('Azure Integration Options')
    azure_group.add_argument("--monitor-conn-str", help="Azure Monitor (App Insights) Connection String. Env: AZURE_MONITOR_CONNECTION_STRING", default=os.environ.get("AZURE_MONITOR_CONNECTION_STRING"))
    azure_group.add_argument("--storage-conn-str", help="Azure Storage Account Connection String. Env: AZURE_STORAGE_CONNECTION_STRING", default=os.environ.get("AZURE_STORAGE_CONNECTION_STRING"))
    azure_group.add_argument("--blacklist-table", help="Azure Table name for blacklist (default: blacklistips). Env: AZURE_BLACKLIST_TABLE", default=os.environ.get("AZURE_BLACKLIST_TABLE", "blacklistips"))

    threshold_group = parser.add_argument_group('Analysis Thresholds')
    threshold_group.add_argument("--long-conn-threshold", type=int, default=3600, help="Threshold for long-lived connections in seconds (default: 3600).")
    threshold_group.add_argument("--unusual-port-min", type=int, default=1024, help="Min port number considered unusual if not common (default: 1024).")
    threshold_group.add_argument("--flow-timeout", type=int, default=300, help="Flow inactivity timeout in seconds for live mode (default: 300).")
    threshold_group.add_argument("--local-blacklist", default="malicious_ips.txt", help="Path to local IP/domain blacklist file (default: malicious_ips.txt).")
    
    args = parser.parse_args()

    # Initialize analyzer_instance here so it's available for signal_handler early
    # and logger is configured before any major operations.
    analyzer_instance = PcapAnalyzer(
        monitor_conn_str=args.monitor_conn_str,
        storage_conn_str=args.storage_conn_str,
        blacklist_table_name=args.blacklist_table
    )

    analyzer_instance.long_connection_threshold_seconds = args.long_conn_threshold
    analyzer_instance.unusual_port_min_threshold = args.unusual_port_min
    analyzer_instance.local_blacklist_file = args.local_blacklist
    analyzer_instance.flow_timeout_seconds = args.flow_timeout
    
    # If local_blacklist path was changed by arg, reload IPs after initial PcapAnalyzer init (which loads default)
    if args.local_blacklist != "malicious_ips.txt": 
        analyzer_instance.logger.info(f"Non-default local blacklist specified ('{args.local_blacklist}'). Reloading IPs.")
        analyzer_instance._load_malicious_ips() # Reload with the potentially new path

    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)  # Handles Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler) # Handles termination signal (e.g., from `kill`)

    try:
        if args.pcap_file:
            analyzer_instance.process_pcap_file(args.pcap_file)
        elif args.interface:
            analyzer_instance.start_live_capture(args.interface, args.bpf_filter)
    except KeyboardInterrupt: # Explicitly catch KeyboardInterrupt here if Ctrl+C is not fully handled by signal
        analyzer_instance.logger.info("KeyboardInterrupt caught in main. Shutting down...")
        if analyzer_instance:
             analyzer_instance.live_capture_stop_event.set() # Ensure stop event is set
    except Exception as e: 
        if analyzer_instance and analyzer_instance.logger:
            analyzer_instance.logger.critical(f"A critical error occurred in main execution: {e}", exc_info=True)
        else: # Logger might not be initialized if error is very early
            print(f"A critical error occurred in main execution before logger was ready: {e}")
    finally:
        if analyzer_instance: # Ensure instance exists before trying to call methods on it
            # The live_capture_stop_event should already be set by signal_handler or KeyboardInterrupt
            # Final cleanup in start_live_capture's finally block should handle flow_analyzer_thread
            if AZURE_SDK_AVAILABLE:
                analyzer_instance.shutdown_otel()
            analyzer_instance.logger.info("Analyzer finished.")
        else:
            print("Analyzer instance was not fully initialized. Exiting.")


if __name__ == "__main__":
    # Basic check if Scapy's core components seem available
    # (Scapy_Exception would be defined if `from scapy.error import Scapy_Exception` succeeded)
    if 'Scapy_Exception' not in globals(): 
        # This message is printed at the top if initial Scapy import fails.
        # This is a fallback, but the exit(1) at the top should prevent reaching here.
        print("Exiting: Scapy core components failed to import. Please check installation.")
    else:
        main()
