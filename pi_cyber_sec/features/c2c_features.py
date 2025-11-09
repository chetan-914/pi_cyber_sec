# pi_cyber_sec/features/port_scan_features.py

from .feature_extractor import FeatureExtractor
from scapy.all import TCP, IP
from collections import defaultdict
from typing import List, Dict, Any

class PortScanFeatureExtractor(FeatureExtractor):
    """
    Extracts features for Port Scan attack detection from a window of packets.
    """
    def extract_features(self, packets: List) -> List[Dict[str, Any]]:
        """
        Aggregates connection attempts from source IPs to detect port scanning.

        :param packets: A list of scapy packets.
        :return: A list of dictionaries, one for each source IP.
        """
        if not packets:
            return []

        # Group packets by source IP
        src_ip_activity = defaultdict(lambda: {'syn_count': 0, 'dst_ports': set()})
        
        for pkt in packets:
            if IP in pkt and TCP in pkt:
                src_ip = pkt[IP].src
                # Count SYN packets (connection attempts)
                if pkt[TCP].flags == 'S':
                    src_ip_activity[src_ip]['syn_count'] += 1
                    src_ip_activity[src_ip]['dst_ports'].add(pkt[TCP].dport)

        features = []
        for ip, activity in src_ip_activity.items():
            features.append({
                'src_ip': ip,
                'connection_attempts': activity['syn_count'],
                'unique_ports_scanned': len(activity['dst_ports']),
            })
            
        return features