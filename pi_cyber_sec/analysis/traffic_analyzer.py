# pi_cyber_sec/analysis/traffic_analyzer.py

import joblib
import pandas as pd
import logging
from typing import List, Dict, Any

class TrafficAnalyzer:
    """
    Analyzes network traffic features using a pre-trained machine learning model
    to detect cyberattacks.
    """
    def __init__(self, model_path: str):
        """
        Initializes the TrafficAnalyzer.

        :param model_path: The file path to the trained model (e.g., a .pkl file).
        """
        self.model = self._load_model(model_path)

    def _load_model(self, model_path: str) -> Any:
        """
        Loads a trained machine learning model from a file.
        """
        try:
            model = joblib.load(model_path)
            logging.info(f"Successfully loaded model from '{model_path}'.")
            return model
        except FileNotFoundError:
            logging.error(f"Model file not found at '{model_path}'.")
            return None
        except Exception as e:
            logging.error(f"Error loading model: {e}")
            return None

    def detect_attack(self, features: List[Dict[str, Any]]) -> List:
        """
        Detects attacks based on the extracted features.

        :param features: A list of feature dictionaries.
        :return: A list of predictions for each feature set.
        """
        if self.model is None or not features:
            return []

        try:
            # Convert list of feature dicts to a Pandas DataFrame
            # The training script must ensure columns are in the same order
            df = pd.DataFrame(features)
            
            # Ensure all required columns for the model are present
            # This is a simple way; a more robust solution would save feature names with the model
            model_features = getattr(self.model, 'feature_names_in_', None)
            if model_features is not None:
                for col in model_features:
                    if col not in df.columns:
                        df[col] = 0 # Add missing columns with a default value
                df = df[model_features] # Ensure order is correct

            predictions = self.model.predict(df)
            return predictions.tolist()
        except Exception as e:
            logging.error(f"Error during prediction: {e}")
            return []