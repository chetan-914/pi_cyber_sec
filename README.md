# Pi Cyber-Security Library

A Python library for real-time cyberattack detection on a Raspberry Pi configured as a network router. This library captures network traffic, extracts features, and uses machine learning models to identify malicious activities like DoS attacks and port scanning.

## Features

- **Live Packet Capture:** Captures network traffic from any specified interface.
- **Modular Feature Extraction:** Easily extendable system for adding new feature extractors for different attack types.
- **Machine Learning-Based Detection:** Uses trained models to classify traffic as normal or malicious.
- **Extensible Structure:** Designed for easy addition of new attack detection modules.

## Project Structure