# pi_cyber_sec/features/dos_features.py

from .feature_extractor import FeatureExtractor
from collections import Counter
from scapy.all import IP, TCP, UDP
import numpy as np
from typing import List, Dict, Any

class DoSFeatureExtractor(FeatureExtractor):
    """
    Extracts features relevant for DoS attack detection from a window of packets.
    Attempts to match the feature set used by the Raspberry Pi monitoring code:
      [avg_packet_size,
       packets_per_sec,
       flow_duration,
       bytes_per_sec,
       total_connections,
       port_diversity,
       tcp_ratio,
       udp_ratio,
       syn_ratio_approx,   # used as SYN_Flag_Ratio approximation
       ack_ratio_approx]   # used as ACK_Flag_Ratio approximation (1 - syn_ratio_approx)
    """

    def extract_features(self, packets: List) -> List[Dict[str, Any]]:
        """
        Extracts DoS-related features from a list of scapy packets within a time window.

        :param packets: A list of scapy packets.
        :return: A list containing a single dictionary of aggregated features.
        """
        if not packets:
            return []

        # Time window duration (use first and last packet timestamps)
        first_packet_time = getattr(packets[0], "time", None)
        last_packet_time = getattr(packets[-1], "time", None)
        if first_packet_time is None or last_packet_time is None:
            # fallback: treat as 1 second window to avoid div by zero
            duration = 1.0
        else:
            duration = float(last_packet_time - first_packet_time)
            if duration <= 0:
                duration = 1e-6  # Avoid division by zero or negative durations

        total_packets = len(packets)
        packet_rate = total_packets / duration

        # Total bytes seen (sum of captured lengths)
        total_bytes = 0
        # IP related
        src_ips = []
        dst_ips = []
        src_ports = []
        dst_ports = []
        protocols = Counter()
        flows = set()  # unique 5-tuples: (src, dst, sport, dport, proto)

        # TCP/UDP specific counters for flag-based approximations
        tcp_count = 0
        udp_count = 0
        syn_only_count = 0   # SYN packets without ACK (approx half-open attempts)
        ack_flag_count = 0   # TCP packets containing ACK flag (approx ACKs)

        malformed_count = 0

        for pkt in packets:
            try:
                # length: prefer len(pkt) (scapy evaluates to actual packet length)
                pkt_len = len(pkt)
                total_bytes += pkt_len

                if IP in pkt:
                    ip = pkt[IP]
                    src_ips.append(ip.src)
                    dst_ips.append(ip.dst)
                    proto = ip.proto  # numeric
                else:
                    # no IP layer — treat as "other" protocol
                    proto = None

                sport = None
                dport = None
                proto_name = "OTHER"

                # TCP
                if TCP in pkt:
                    tcp_count += 1
                    proto_name = "TCP"
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    # scapy represents flags as an int or string; convert to str
                    flags = bytes(pkt[TCP].flags).decode(errors='ignore') if isinstance(pkt[TCP].flags, bytes) else str(pkt[TCP].flags)
                    # easier check: look for 'S' and 'A' in flags string representation
                    if 'S' in flags and 'A' not in flags:
                        syn_only_count += 1
                    if 'A' in flags:
                        ack_flag_count += 1

                # UDP
                elif UDP in pkt:
                    udp_count += 1
                    proto_name = "UDP"
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport

                else:
                    # could attempt to parse other L4s, but skip for now
                    pass

                if sport is not None:
                    src_ports.append(sport)
                if dport is not None:
                    dst_ports.append(dport)

                # flow tuple
                flows.add((getattr(pkt.payload, "src", None) or getattr(pkt, "src", None),
                           getattr(pkt.payload, "dst", None) or getattr(pkt, "dst", None),
                           sport, dport, proto_name))

                if proto_name:
                    protocols[proto_name] += 1
                else:
                    protocols["OTHER"] += 1

            except Exception:
                # keep moving, but count malformed packets
                malformed_count += 1
                continue

        bytes_per_sec = total_bytes / duration
        packets_per_sec = packet_rate
        avg_packet_size = (total_bytes / total_packets) if total_packets > 0 else 0

        total_connections = len(flows)  # approximate unique connections / flows

        # Port diversity: number of distinct destination ports seen (simple proxy)
        port_diversity = len(set(dst_ports)) if dst_ports else 0

        # TCP/UDP ratios
        total_proto_count = tcp_count + udp_count if (tcp_count + udp_count) > 0 else total_packets
        tcp_ratio = (tcp_count / total_proto_count) if total_proto_count > 0 else 0.0
        udp_ratio = (udp_count / total_proto_count) if total_proto_count > 0 else 0.0

        # Approximate 'error_rate' used in original script:
        # original derived error_rate from system counters (errin/errout).
        # Here we approximate a suspicious "error-like" event rate by
        # counting SYN-only packets (possible half-open attempts) plus malformed packets.
        syn_rate = syn_only_count / duration
        malformed_rate = malformed_count / duration
        approx_error_rate = syn_rate + malformed_rate

        # Normalize SYN-based ratio relative to packet rate similar to original code:
        syn_flag_ratio_approx = approx_error_rate / (packets_per_sec + 1)
        ack_flag_ratio_approx = 1 - syn_flag_ratio_approx

        # Entropy of source IPs (useful signal)
        src_ip_counts = Counter(src_ips)
        if src_ips:
            probabilities = [count / len(src_ips) for count in src_ip_counts.values()]
            src_ip_entropy = -sum(p * np.log2(p) for p in probabilities)
        else:
            src_ip_entropy = 0.0

        features = {
            # Matching the vector used by NetworkMonitor.calculate_traffic_features:
            'avg_packet_size': float(avg_packet_size),         # Packet_Size
            'packets_per_sec': float(packets_per_sec),         # Packets_Per_Sec
            'flow_duration': float(duration),                  # Flow_Duration
            'bytes_per_sec': float(bytes_per_sec),             # Bytes_Per_Sec
            'total_connections': int(total_connections),       # Unique_IPs (approx)
            'port_diversity': int(port_diversity),             # Port_Diversity
            'tcp_ratio': float(tcp_ratio),                     # TCP_Ratio
            'udp_ratio': float(udp_ratio),                     # UDP_Ratio
            'syn_flag_ratio_approx': float(syn_flag_ratio_approx),  # SYN_Flag_Ratio (approx)
            'ack_flag_ratio_approx': float(ack_flag_ratio_approx),  # ACK_Flag_Ratio (approx)
            # Additional useful fields:
            'total_packets': int(total_packets),
            'total_bytes': int(total_bytes),
            'unique_src_ips': int(len(src_ip_counts)),
            'src_ip_entropy': float(src_ip_entropy),
            'malformed_packets': int(malformed_count),
            'tcp_packets': int(tcp_count),
            'udp_packets': int(udp_count),
            'protocol_counts': dict(protocols),
        }

        # Also provide a numpy array feature vector in same order as original ML input
        feature_vector = np.array([
            features['avg_packet_size'],
            features['packets_per_sec'],
            features['flow_duration'],
            features['bytes_per_sec'],
            features['total_connections'],
            features['port_diversity'] if features['port_diversity'] > 0 else 1,  # keep >0 like original simplified '1'
            features['tcp_ratio'],
            features['udp_ratio'],
            features['syn_flag_ratio_approx'],
            features['ack_flag_ratio_approx']
        ], dtype=float)

        features['feature_vector'] = feature_vector

        return [features]
