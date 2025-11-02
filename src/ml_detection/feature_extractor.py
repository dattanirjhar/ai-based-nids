"""
Machine Learning Feature Extractor Module
Transforms raw network data into ML-ready feature vectors with normalization and selection
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple, Optional, Union
from dataclasses import dataclass
from sklearn.preprocessing import StandardScaler, MinMaxScaler, LabelEncoder
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif
import joblib
import os
import logging
from collections import defaultdict
import time

from ..network_monitor.traffic_features import FlowFeatures, WindowFeatures
from ..config.settings import get_config

logger = logging.getLogger(__name__)


@dataclass
class FeatureSet:
    """Container for extracted features and metadata"""
    features: np.ndarray
    feature_names: List[str]
    feature_types: List[str]  # 'numerical', 'categorical', 'binary'
    timestamps: Optional[List[float]] = None
    labels: Optional[np.ndarray] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class FeatureExtractionResult:
    """Result of feature extraction process"""
    feature_set: FeatureSet
    extraction_time: float
    sample_count: int
    feature_count: int
    scaling_applied: bool
    selection_applied: bool


class MLFeatureExtractor:
    """
    Transforms network traffic data into ML-ready features with normalization and selection
    """

    def __init__(self,
                 scaler_type: str = 'standard',
                 selection_method: str = 'mutual_info',
                 n_features_to_select: int = 20):
        """
        Initialize ML feature extractor

        Args:
            scaler_type: Type of scaler ('standard', 'minmax', 'none')
            selection_method: Feature selection method ('mutual_info', 'f_classif', 'none')
            n_features_to_select: Number of features to select
        """
        self.config = get_config()
        self.scaler_type = scaler_type
        self.selection_method = selection_method
        self.n_features_to_select = n_features_to_select

        # Initialize scalers
        self.scalers: Dict[str, Any] = {}
        self._initialize_scalers()

        # Initialize feature selectors
        self.feature_selectors: Dict[str, Any] = {}
        self._initialize_selectors()

        # Feature engineering settings
        self.feature_config = self.config.get_section('ml').get('detection', {})
        self.confidence_threshold = self.feature_config.get('confidence_threshold', 0.7)

        # Feature mappings and encoders
        self.protocol_encoder = LabelEncoder()
        self.port_category_encoder = LabelEncoder()
        self.feature_mappings: Dict[str, Dict[str, int]] = {}

        # Feature statistics for online normalization
        self.feature_stats: Dict[str, Dict[str, float]] = {}
        self.online_mode = False

        # Load saved models if available
        self._load_saved_models()

    def _initialize_scalers(self):
        """Initialize feature scalers"""
        if self.scaler_type == 'standard':
            self.scalers['numerical'] = StandardScaler()
        elif self.scaler_type == 'minmax':
            self.scalers['numerical'] = MinMaxScaler()
        elif self.scaler_type != 'none':
            logger.warning(f"Unknown scaler type: {self.scaler_type}, using standard")
            self.scalers['numerical'] = StandardScaler()

    def _initialize_selectors(self):
        """Initialize feature selectors"""
        if self.selection_method == 'mutual_info':
            self.feature_selectors['numerical'] = SelectKBest(
                score_func=mutual_info_classif,
                k=self.n_features_to_select
            )
        elif self.selection_method == 'f_classif':
            self.feature_selectors['numerical'] = SelectKBest(
                score_func=f_classif,
                k=self.n_features_to_select
            )
        elif self.selection_method != 'none':
            logger.warning(f"Unknown selection method: {self.selection_method}, using mutual_info")
            self.feature_selectors['numerical'] = SelectKBest(
                score_func=mutual_info_classif,
                k=self.n_features_to_select
            )

    def extract_flow_features(self, flow_features_list: List[FlowFeatures],
                            labels: Optional[List[str]] = None) -> FeatureExtractionResult:
        """
        Extract features from a list of flow features

        Args:
            flow_features_list: List of FlowFeatures objects
            labels: Optional labels for supervised learning

        Returns:
            FeatureExtractionResult with extracted features
        """
        start_time = time.time()

        if not flow_features_list:
            raise ValueError("No flow features provided")

        # Extract raw features
        raw_features = []
        feature_names = []
        feature_types = []
        timestamps = []

        for i, flow in enumerate(flow_features_list):
            # Extract numerical features
            numerical_features = self._extract_numerical_flow_features(flow)
            raw_features.extend(numerical_features)

            # Extract categorical features
            categorical_features = self._extract_categorical_flow_features(flow)
            raw_features.extend(categorical_features)

            # Extract binary features
            binary_features = self._extract_binary_flow_features(flow)
            raw_features.extend(binary_features)

            # Store timestamp
            timestamps.append(flow.start_time)

            # Store feature names and types (only for first sample)
            if i == 0:
                feature_names = self._get_flow_feature_names()
                feature_types = (['numerical'] * len(numerical_features) +
                               ['categorical'] * len(categorical_features) +
                               ['binary'] * len(binary_features))

        # Convert to numpy array
        features_array = np.array(raw_features).reshape(-1, len(raw_features) // len(flow_features_list)).T

        # Apply feature scaling
        scaling_applied = self._apply_scaling(features_array, feature_types, fit=(labels is not None))

        # Apply feature selection
        selection_applied = False
        if labels and labels[0] is not None:  # Only select features if we have labels
            selection_applied = self._apply_feature_selection(features_array, labels, fit=True)

        # Create feature set
        label_array = np.array(labels) if labels else None
        feature_set = FeatureSet(
            features=features_array,
            feature_names=feature_names,
            feature_types=feature_types,
            timestamps=timestamps,
            labels=label_array,
            metadata={
                'extraction_type': 'flow',
                'sample_count': len(flow_features_list),
                'source_count': len(set(flow.src_ip for flow in flow_features_list)),
                'protocol_distribution': self._get_protocol_distribution(flow_features_list)
            }
        )

        extraction_time = time.time() - start_time

        return FeatureExtractionResult(
            feature_set=feature_set,
            extraction_time=extraction_time,
            sample_count=len(flow_features_list),
            feature_count=features_array.shape[1],
            scaling_applied=scaling_applied,
            selection_applied=selection_applied
        )

    def extract_window_features(self, window_features_list: List[WindowFeatures],
                              labels: Optional[List[str]] = None) -> FeatureExtractionResult:
        """
        Extract features from a list of window features

        Args:
            window_features_list: List of WindowFeatures objects
            labels: Optional labels for supervised learning

        Returns:
            FeatureExtractionResult with extracted features
        """
        start_time = time.time()

        if not window_features_list:
            raise ValueError("No window features provided")

        # Extract raw features
        raw_features = []
        feature_names = []
        feature_types = []
        timestamps = []

        for i, window in enumerate(window_features_list):
            # Extract numerical features
            numerical_features = self._extract_numerical_window_features(window)
            raw_features.extend(numerical_features)

            # Extract categorical features
            categorical_features = self._extract_categorical_window_features(window)
            raw_features.extend(categorical_features)

            # Extract binary features
            binary_features = self._extract_binary_window_features(window)
            raw_features.extend(binary_features)

            # Store timestamp
            timestamps.append(window.window_start)

            # Store feature names and types (only for first sample)
            if i == 0:
                feature_names = self._get_window_feature_names()
                feature_types = (['numerical'] * len(numerical_features) +
                               ['categorical'] * len(categorical_features) +
                               ['binary'] * len(binary_features))

        # Convert to numpy array
        features_array = np.array(raw_features).reshape(-1, len(raw_features) // len(window_features_list)).T

        # Apply feature scaling
        scaling_applied = self._apply_scaling(features_array, feature_types, fit=(labels is not None))

        # Apply feature selection
        selection_applied = False
        if labels and labels[0] is not None:  # Only select features if we have labels
            selection_applied = self._apply_feature_selection(features_array, labels, fit=True)

        # Create feature set
        label_array = np.array(labels) if labels else None
        feature_set = FeatureSet(
            features=features_array,
            feature_names=feature_names,
            feature_types=feature_types,
            timestamps=timestamps,
            labels=label_array,
            metadata={
                'extraction_type': 'window',
                'sample_count': len(window_features_list),
                'avg_window_duration': np.mean([w.window_duration for w in window_features_list])
            }
        )

        extraction_time = time.time() - start_time

        return FeatureExtractionResult(
            feature_set=feature_set,
            extraction_time=extraction_time,
            sample_count=len(window_features_list),
            feature_count=features_array.shape[1],
            scaling_applied=scaling_applied,
            selection_applied=selection_applied
        )

    def _extract_numerical_flow_features(self, flow: FlowFeatures) -> List[float]:
        """Extract numerical features from flow data"""
        return [
            # Basic flow features
            float(flow.packet_count),
            float(flow.byte_count),
            float(flow.duration),

            # Temporal features
            float(flow.packets_per_second),
            float(flow.bytes_per_second),
            float(flow.avg_inter_arrival_time),
            float(flow.std_inter_arrival_time),

            # Packet size features
            float(flow.avg_packet_size),
            float(flow.std_packet_size),
            float(flow.min_packet_size),
            float(flow.max_packet_size),

            # Directional features
            float(flow.src_to_dst_packets),
            float(flow.dst_to_src_packets),
            float(flow.src_to_dst_bytes),
            float(flow.dst_to_src_bytes),

            # Behavioral features
            float(flow.port_scan_indicator),
            float(flow.syn_flood_ratio),
            float(flow.burstiness),
            float(flow.regularity),

            # Port features
            float(flow.src_port),
            float(flow.dst_port),

            # TTL
            float(flow.ttl) if hasattr(flow, 'ttl') else 0.0,
        ]

    def _extract_categorical_flow_features(self, flow: FlowFeatures) -> List[int]:
        """Extract categorical features from flow data"""
        # Protocol encoding
        protocol_encoded = self._encode_protocol(flow.protocol)

        # Port categorization
        src_port_category = self._categorize_port(flow.src_port)
        dst_port_category = self._categorize_port(flow.dst_port)

        return [
            protocol_encoded,
            src_port_category,
            dst_port_category
        ]

    def _extract_binary_flow_features(self, flow: FlowFeatures) -> List[int]:
        """Extract binary features from flow data"""
        return [
            int(flow.is_internal_src),
            int(flow.is_internal_dst),
            int(flow.is_well_known_port),
            int(flow.src_to_dst_packets > flow.dst_to_src_packets),  # Direction bias
            int(flow.duration > 30.0),  # Long duration flow
            int(flow.avg_packet_size > 1000),  # Large packets
            int(flow.packet_count > 100),  # High packet count
        ]

    def _extract_numerical_window_features(self, window: WindowFeatures) -> List[float]:
        """Extract numerical features from window data"""
        return [
            # Aggregate traffic features
            float(window.total_packets),
            float(window.total_bytes),
            float(window.unique_sources),
            float(window.unique_destinations),
            float(window.unique_ports),

            # Traffic patterns
            float(window.new_flows_per_second),
            float(window.avg_flow_duration),
            float(window.flow_diversity),

            # Anomaly scores
            float(window.port_scan_score),
            float(window.dos_score),
            float(window.data_exfiltration_score),
            float(window.unusual_protocol_score),

            # Protocol ratios (numerical)
            float(window.protocol_ratios.get('TCP', 0.0)),
            float(window.protocol_ratios.get('UDP', 0.0)),
            float(window.protocol_ratios.get('ICMP', 0.0)),
        ]

    def _extract_categorical_window_features(self, window: WindowFeatures) -> List[int]:
        """Extract categorical features from window data"""
        # Time of day categorization
        time_category = self._categorize_time_of_day(window.window_start)

        # Dominant protocol
        dominant_protocol = max(window.protocol_ratios.items(), key=lambda x: x[1])[0] if window.protocol_ratios else 'UNKNOWN'
        protocol_encoded = self._encode_protocol(dominant_protocol)

        return [
            time_category,
            protocol_encoded
        ]

    def _extract_binary_window_features(self, window: WindowFeatures) -> List[int]:
        """Extract binary features from window data"""
        return [
            int(window.total_packets > 1000),  # High traffic
            int(window.unique_sources > 100),  # Many sources
            int(window.unique_destinations > 100),  # Many destinations
            int(window.port_scan_score > 0.5),  # Port scan detected
            int(window.dos_score > 0.5),  # DoS detected
            int(window.data_exfiltration_score > 0.5),  # Data exfiltration
            int(window.unusual_protocol_score > 0.5),  # Unusual protocol
        ]

    def _encode_protocol(self, protocol: str) -> int:
        """Encode protocol name to integer"""
        if not hasattr(self, '_protocol_mapping'):
            self._protocol_mapping = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'UNKNOWN': 3}

        return self._protocol_mapping.get(protocol.upper(), 3)

    def _categorize_port(self, port: int) -> int:
        """Categorize port number"""
        if port == 0:
            return 0  # No port
        elif 1 <= port <= 1023:
            return 1  # Well-known
        elif 1024 <= port <= 49151:
            return 2  # Registered
        else:
            return 3  # Dynamic/Private

    def _categorize_time_of_day(self, timestamp: float) -> int:
        """Categorize time of day"""
        hour = time.localtime(timestamp).tm_hour
        if 6 <= hour < 12:
            return 0  # Morning
        elif 12 <= hour < 18:
            return 1  # Afternoon
        elif 18 <= hour < 24:
            return 2  # Evening
        else:
            return 3  # Night

    def _get_flow_feature_names(self) -> List[str]:
        """Get list of flow feature names"""
        return [
            # Numerical features
            'packet_count', 'byte_count', 'duration',
            'packets_per_second', 'bytes_per_second',
            'avg_inter_arrival_time', 'std_inter_arrival_time',
            'avg_packet_size', 'std_packet_size',
            'min_packet_size', 'max_packet_size',
            'src_to_dst_packets', 'dst_to_src_packets',
            'src_to_dst_bytes', 'dst_to_src_bytes',
            'port_scan_indicator', 'syn_flood_ratio',
            'burstiness', 'regularity',
            'src_port', 'dst_port', 'ttl',
            # Categorical features
            'protocol', 'src_port_category', 'dst_port_category',
            # Binary features
            'is_internal_src', 'is_internal_dst', 'is_well_known_port',
            'direction_bias', 'is_long_duration', 'has_large_packets', 'has_high_packet_count'
        ]

    def _get_window_feature_names(self) -> List[str]:
        """Get list of window feature names"""
        return [
            # Numerical features
            'total_packets', 'total_bytes', 'unique_sources',
            'unique_destinations', 'unique_ports',
            'new_flows_per_second', 'avg_flow_duration', 'flow_diversity',
            'port_scan_score', 'dos_score', 'data_exfiltration_score', 'unusual_protocol_score',
            'tcp_ratio', 'udp_ratio', 'icmp_ratio',
            # Categorical features
            'time_category', 'dominant_protocol',
            # Binary features
            'is_high_traffic', 'has_many_sources', 'has_many_destinations',
            'has_port_scan', 'has_dos', 'has_data_exfiltration', 'has_unusual_protocol'
        ]

    def _apply_scaling(self, features: np.ndarray, feature_types: List[str], fit: bool = False) -> bool:
        """Apply feature scaling"""
        if self.scaler_type == 'none':
            return False

        # Find indices of numerical features
        numerical_indices = [i for i, ftype in enumerate(feature_types) if ftype == 'numerical']

        if not numerical_indices:
            return False

        # Extract numerical features
        numerical_features = features[:, numerical_indices]

        # Apply scaling
        if fit:
            if 'numerical' in self.scalers:
                features[:, numerical_indices] = self.scalers['numerical'].fit_transform(numerical_features)
        else:
            if 'numerical' in self.scalers and hasattr(self.scalers['numerical'], 'mean_'):
                features[:, numerical_indices] = self.scalers['numerical'].transform(numerical_features)
            else:
                # Fallback to online scaling using stored statistics
                features[:, numerical_indices] = self._apply_online_scaling(numerical_features)

        return True

    def _apply_online_scaling(self, features: np.ndarray) -> np.ndarray:
        """Apply online scaling using stored statistics"""
        scaled_features = np.zeros_like(features)

        for i in range(features.shape[1]):
            feature_name = f'feature_{i}'
            if feature_name in self.feature_stats:
                stats = self.feature_stats[feature_name]
                mean = stats['mean']
                std = stats['std']

                if std > 0:
                    scaled_features[:, i] = (features[:, i] - mean) / std
                else:
                    scaled_features[:, i] = features[:, i] - mean
            else:
                # If no stats available, use z-score normalization on current data
                col_data = features[:, i]
                if np.std(col_data) > 0:
                    scaled_features[:, i] = (col_data - np.mean(col_data)) / np.std(col_data)
                else:
                    scaled_features[:, i] = col_data - np.mean(col_data)

        return scaled_features

    def _apply_feature_selection(self, features: np.ndarray, labels: List[str], fit: bool = False) -> bool:
        """Apply feature selection"""
        if self.selection_method == 'none':
            return False

        # Convert labels to numeric if needed
        if isinstance(labels[0], str):
            label_encoder = LabelEncoder()
            numeric_labels = label_encoder.fit_transform(labels)
        else:
            numeric_labels = np.array(labels)

        # Apply selection
        if fit and 'numerical' in self.feature_selectors:
            selected_features = self.feature_selectors['numerical'].fit_transform(features, numeric_labels)
        elif 'numerical' in self.feature_selectors and hasattr(self.feature_selectors['numerical'], 'scores_'):
            selected_features = self.feature_selectors['numerical'].transform(features)
        else:
            return False

        # Update features array
        if selected_features.shape[1] > 0:
            # Resize features array to selected features
            new_features = np.zeros((features.shape[0], selected_features.shape[1]))
            new_features[:] = selected_features
            return True

        return False

    def _get_protocol_distribution(self, flow_features_list: List[FlowFeatures]) -> Dict[str, float]:
        """Calculate protocol distribution from flow features"""
        protocol_counts = defaultdict(int)
        total_flows = len(flow_features_list)

        for flow in flow_features_list:
            protocol_counts[flow.protocol] += 1

        return {protocol: count / total_flows for protocol, count in protocol_counts.items()}

    def transform_single_sample(self, flow_features: FlowFeatures) -> np.ndarray:
        """
        Transform a single sample for online prediction

        Args:
            flow_features: Single FlowFeatures object

        Returns:
            Transformed feature vector
        """
        # Extract features
        numerical = self._extract_numerical_flow_features(flow_features)
        categorical = self._extract_categorical_flow_features(flow_features)
        binary = self._extract_binary_flow_features(flow_features)

        # Combine features
        features = np.array(numerical + categorical + binary).reshape(1, -1)

        # Apply scaling (without fitting)
        feature_types = (['numerical'] * len(numerical) +
                        ['categorical'] * len(categorical) +
                        ['binary'] * len(binary))
        self._apply_scaling(features, feature_types, fit=False)

        return features

    def save_models(self, model_dir: str):
        """Save fitted scalers and selectors"""
        os.makedirs(model_dir, exist_ok=True)

        # Save scalers
        if 'numerical' in self.scalers and hasattr(self.scalers['numerical'], 'mean_'):
            joblib.dump(self.scalers['numerical'], os.path.join(model_dir, 'feature_scaler.pkl'))

        # Save feature selectors
        if 'numerical' in self.feature_selectors and hasattr(self.feature_selectors['numerical'], 'scores_'):
            joblib.dump(self.feature_selectors['numerical'], os.path.join(model_dir, 'feature_selector.pkl'))

        # Save feature statistics
        joblib.dump(self.feature_stats, os.path.join(model_dir, 'feature_stats.pkl'))

        # Save feature mappings
        joblib.dump(self.feature_mappings, os.path.join(model_dir, 'feature_mappings.pkl'))

        logger.info(f"Feature extraction models saved to {model_dir}")

    def _load_saved_models(self):
        """Load saved scalers and selectors"""
        model_dir = self.config.get('ml.model_directory', 'data/models')

        try:
            # Load scalers
            scaler_path = os.path.join(model_dir, 'feature_scaler.pkl')
            if os.path.exists(scaler_path):
                self.scalers['numerical'] = joblib.load(scaler_path)
                logger.info("Loaded feature scaler")

            # Load feature selectors
            selector_path = os.path.join(model_dir, 'feature_selector.pkl')
            if os.path.exists(selector_path):
                self.feature_selectors['numerical'] = joblib.load(selector_path)
                logger.info("Loaded feature selector")

            # Load feature statistics
            stats_path = os.path.join(model_dir, 'feature_stats.pkl')
            if os.path.exists(stats_path):
                self.feature_stats = joblib.load(stats_path)
                logger.info("Loaded feature statistics")

            # Load feature mappings
            mappings_path = os.path.join(model_dir, 'feature_mappings.pkl')
            if os.path.exists(mappings_path):
                self.feature_mappings = joblib.load(mappings_path)
                logger.info("Loaded feature mappings")

        except Exception as e:
            logger.error(f"Error loading feature extraction models: {e}")

    def get_feature_importance(self) -> Optional[Dict[str, float]]:
        """Get feature importance scores if available"""
        if 'numerical' in self.feature_selectors and hasattr(self.feature_selectors['numerical'], 'scores_'):
            feature_names = self._get_flow_feature_names()
            scores = self.feature_selectors['numerical'].scores_

            return dict(zip(feature_names, scores))

        return None

    def update_online_statistics(self, features: np.ndarray):
        """Update online feature statistics for scaling"""
        for i in range(features.shape[1]):
            feature_name = f'feature_{i}'
            if feature_name not in self.feature_stats:
                self.feature_stats[feature_name] = {
                    'mean': 0.0,
                    'std': 1.0,
                    'count': 0,
                    'sum': 0.0,
                    'sum_sq': 0.0
                }

            # Update running statistics
            stats = self.feature_stats[feature_name]
            stats['count'] += features.shape[0]
            stats['sum'] += np.sum(features[:, i])
            stats['sum_sq'] += np.sum(features[:, i] ** 2)

            # Calculate mean and std
            if stats['count'] > 0:
                stats['mean'] = stats['sum'] / stats['count']
                variance = (stats['sum_sq'] / stats['count']) - (stats['mean'] ** 2)
                stats['std'] = np.sqrt(max(variance, 0))

    def get_feature_statistics(self) -> Dict[str, Any]:
        """Get current feature statistics"""
        return {
            'scaler_type': self.scaler_type,
            'selection_method': self.selection_method,
            'n_features_to_select': self.n_features_to_select,
            'feature_mappings_count': len(self.feature_mappings),
            'feature_stats_count': len(self.feature_stats),
            'scalers_fitted': len([s for s in self.scalers.values() if hasattr(s, 'mean_')]),
            'selectors_fitted': len([s for s in self.feature_selectors.values() if hasattr(s, 'scores_')])
        }


# Global feature extractor instance
_ml_feature_extractor_instance = None

def get_ml_feature_extractor() -> MLFeatureExtractor:
    """Get or create the global ML feature extractor instance"""
    global _ml_feature_extractor_instance
    if _ml_feature_extractor_instance is None:
        _ml_feature_extractor_instance = MLFeatureExtractor()
    return _ml_feature_extractor_instance

def cleanup_ml_feature_extractor():
    """Cleanup the global ML feature extractor instance"""
    global _ml_feature_extractor_instance
    _ml_feature_extractor_instance = None