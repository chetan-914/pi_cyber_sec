# pi_cyber_sec/features/mitm_features.py

from .feature_extractor import FeatureExtractor
from scapy.all import ARP
from collections import defaultdict
from typing import List, Dict, Any

class MitMFeatureExtractor(FeatureExtractor):
    """
    Extracts features for MitM (ARP spoofing) attack detection.
    """
    def extract_features(self, packets: List) -> List[Dict[str, Any]]:
        """
        Detects potential ARP spoofing by looking for duplicate ARP responses.

        :param packets: A list of scapy packets.
        :return: A list of dictionaries detailing suspicious activity.
        """
        # Maps an IP address to a MAC address seen in ARP responses
        ip_to_mac = defaultdict(set)
        suspicious_activity = []
        
        # Filter for ARP "is-at" responses
        arp_responses = [pkt for pkt in packets if ARP in pkt and pkt[ARP].op == 2]

        for pkt in arp_responses:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            
            # Check if this IP was previously associated with a different MAC
            if ip_to_mac[ip] and mac not in ip_to_mac[ip]:
                suspicious_activity.append({
                    'alert': 'Potential ARP Spoofing',
                    'ip_address': ip,
                    'new_mac': mac,
                    'previous_macs': list(ip_to_mac[ip])
                })
            
            ip_to_mac[ip].add(mac)

        return suspicious_activity