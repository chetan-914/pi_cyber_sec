# pi_cyber_sec/capture/packet_capturer.py

from scapy.all import sniff, wrpcap, AsyncSniffer
from typing import List
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PacketCapturer:
    """
    A class to capture network packets using scapy's AsyncSniffer
    for non-blocking packet sniffing.
    """
    def __init__(self, interface: str, capture_filter: str = "ip"):
        """
        Initializes the PacketCapturer.

        :param interface: The network interface to capture packets from (e.g., 'eth0').
        :param capture_filter: BPF filter for capturing specific packets (e.g., 'tcp').
        """
        self.interface = interface
        self.capture_filter = capture_filter
        self.sniffer = None
        self.packets = []

    def start_capture(self):
        """
        Starts the packet capture in a non-blocking manner.
        """
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.capture_filter,
            prn=self._process_packet,
            store=False  # Do not store packets in memory by default
        )
        self.sniffer.start()
        logging.info(f"Started packet capture on interface '{self.interface}'.")

    def _process_packet(self, packet):
        """
        Callback function to process each captured packet.
        """
        self.packets.append(packet)

    def stop_capture(self) -> List:
        """
        Stops the packet capture and returns the captured packets.

        :return: A list of captured scapy packets.
        """
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
            logging.info("Stopped packet capture.")
        
        # Return a copy and clear the internal list for the next run
        captured_packets = self.packets.copy()
        self.packets.clear()
        return captured_packets

    def save_to_pcap(self, filename: str, packets: List):
        """
        Saves a list of captured packets to a pcap file.

        :param filename: The name of the file to save the packets to.
        :param packets: The list of packets to save.
        """
        if not packets:
            logging.warning("No packets to save.")
            return
        
        try:
            wrpcap(filename, packets)
            logging.info(f"Saved {len(packets)} packets to '{filename}'.")
        except Exception as e:
            logging.error(f"Failed to save pcap file: {e}")