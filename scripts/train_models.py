# pi_cyber_sec/scripts/train_models.py

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scapy.all import rdpcap
from pi_cyber_sec.features.dos_features import DoSFeatureExtractor
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pandas as pd
import joblib
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def train_dos_model():
    """
    A sample function to train a DoS detection model.
    """
    logging.info("Starting DoS model training...")
    
    # --- Data Loading and Feature Extraction ---
    # In a real scenario, you'd have labeled pcap files.
    # We'll simulate this with placeholder files.
    # PLEASE REPLACE 'data/raw/normal_traffic.pcap' and 'data/raw/dos_attack.pcap'
    # with your actual data.

    try:
        normal_packets = rdpcap('data/raw/normal_traffic.pcap')
        attack_packets = rdpcap('data/raw/dos_attack.pcap')
    except FileNotFoundError:
        logging.error("Pcap files for training not found. Please create 'data/raw/normal_traffic.pcap' and 'data/raw/dos_attack.pcap'.")
        return

    extractor = DoSFeatureExtractor()
    
    # Extract features and label them
    # For simplicity, we process the whole file as one window.
    # A better approach is to use sliding windows.
    normal_features = extractor.extract_features(normal_packets)
    attack_features = extractor.extract_features(attack_packets)
    
    # Label: 0 for normal, 1 for attack
    for f in normal_features: f['label'] = 0
    for f in attack_features: f['label'] = 1
        
    all_features = normal_features + attack_features
    if not all_features:
        logging.error("No features were extracted. Cannot train model.")
        return
        
    df = pd.DataFrame(all_features)
    
    # --- Model Training ---
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Ensure feature names are stored for later prediction
    feature_names = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    logging.info(f"Training on {len(X_train)} samples, testing on {len(X_test)} samples.")
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Store feature names in the model object
    model.feature_names_in_ = feature_names

    # --- Evaluation ---
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    logging.info(f"Model Accuracy: {accuracy * 100:.2f}%")

    # --- Save Model ---
    model_dir = 'pi_cyber_sec/models'
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, 'dos_model.pkl')
    joblib.dump(model, model_path)
    logging.info(f"DoS model saved to '{model_path}'.")


if __name__ == "__main__":
    # Create dummy pcap files if they don't exist, for demonstration purposes
    from scapy.all import IP, TCP, Ether, wrpcap
    os.makedirs('data/raw', exist_ok=True)
    if not os.path.exists('data/raw/normal_traffic.pcap'):
        pkts = [Ether()/IP(src=f"192.168.1.{i}", dst="192.168.1.100")/TCP() for i in range(20)]
        wrpcap('data/raw/normal_traffic.pcap', pkts)
    if not os.path.exists('data/raw/dos_attack.pcap'):
        pkts = [Ether()/IP(src=f"10.0.0.{i}", dst="192.168.1.100")/TCP() for i in range(200)]
        wrpcap('data/raw/dos_attack.pcap', pkts)
        
    train_dos_model()