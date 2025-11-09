# pi_cyber_sec/features/feature_extractor.py

from abc import ABC, abstractmethod
from typing import List, Dict, Any

class FeatureExtractor(ABC):
    """
    Abstract base class for feature extraction.
    All specific feature extractors should inherit from this class.
    """
    @abstractmethod
    def extract_features(self, packets: List) -> List[Dict[str, Any]]:
        """
        Extracts features from a list of packets.

        :param packets: A list of scapy packets.
        :return: A list of dictionaries, where each dictionary represents the features of a flow or a time window.
        """
        raise NotImplementedError