# scripts/run_live_detection.py

import sys
import os
import time
import logging
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pi_cyber_sec.capture.packet_capturer import PacketCapturer
from pi_cyber_sec.features.dos_features import DoSFeatureExtractor
from pi_cyber_sec.analysis.traffic_analyzer import TrafficAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    """
    Main function to run the live cyberattack detection.
    """
    # Configuration
    INTERFACE = "eth0"  # IMPORTANT: Change to your Raspberry Pi's network interface
    CAPTURE_INTERVAL = 10  # Time in seconds for each capture window
    DOS_MODEL_PATH = "pi_cyber_sec/models/ddos_model.joblib"

    # Initialization
    if not os.path.exists(DOS_MODEL_PATH):
        logging.error(f"Model not found at {DOS_MODEL_PATH}. Please run the training script first.")
        return

    packet_capturer = PacketCapturer(interface=INTERFACE)
    dos_feature_extractor = DoSFeatureExtractor()
    dos_analyzer = TrafficAnalyzer(DOS_MODEL_PATH)

    logging.info(f"Starting live cyberattack detection on interface '{INTERFACE}'.")
    logging.info(f"Analyzing traffic in {CAPTURE_INTERVAL}-second windows.")

    try:
        packet_capturer.start_capture()
        while True:
            # Wait for the specified interval
            time.sleep(CAPTURE_INTERVAL)
            
            # Stop capture momentarily to process packets
            packets = packet_capturer.stop_capture()
            logging.info(f"Processing {len(packets)} packets captured in the last window.")
            
            # Restart capture immediately to minimize packet loss
            packet_capturer.start_capture()
            
            if packets:
                # --- DoS Attack Detection ---
                dos_features = dos_feature_extractor.extract_features(packets)
                if dos_features:
                    predictions = dos_analyzer.detect_attack(dos_features)
                    # The model predicts for the entire window.
                    # Prediction '1' means an attack is likely.
                    if predictions and predictions[0] == 1:
                        logging.warning(f"DoS ATTACK DETECTED! Features: {dos_features[0]}")
                    else:
                        logging.info("Traffic appears normal (No DoS).")

                # --- Add other attack detection modules here ---
                # e.g., port_scan_features = port_scan_extractor.extract_features(packets)
                #       port_scan_analyzer.detect_attack(port_scan_features)

    except KeyboardInterrupt:
        logging.info("Detection stopped by user.")
    finally:
        if packet_capturer.sniffer and packet_capturer.sniffer.running:
            packet_capturer.stop_capture()

if __name__ == "__main__":
    main()
    