"""
Anomaly Detector Module
Real-time anomaly detection using trained ML models with ensemble voting
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from collections import deque
import time
import logging
import joblib
import os
from datetime import datetime

from .feature_extractor import MLFeatureExtractor
from .model_trainer import ModelTrainer
from ..network_monitor.traffic_features import FlowFeatures, WindowFeatures
from ..config.settings import get_config

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Result of anomaly detection for a single sample"""
    timestamp: float
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    model_predictions: Dict[str, Dict[str, Any]]
    detection_method: str
    feature_vector: Optional[np.ndarray] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AnomalyStatistics:
    """Statistics about anomaly detection performance"""
    total_samples: int
    anomaly_count: int
    normal_count: int
    anomaly_rate: float
    avg_confidence: float
    avg_anomaly_score: float
    model_usage_stats: Dict[str, int]
    detection_latency: float


class AnomalyDetector:
    """
    Real-time anomaly detection system using ensemble of ML models
    """

    def __init__(self, model_trainer: Optional[ModelTrainer] = None):
        """
        Initialize anomaly detector

        Args:
            model_trainer: Trained ModelTrainer instance
        """
        self.config = get_config()
        self.model_trainer = model_trainer or ModelTrainer()
        self.feature_extractor = MLFeatureExtractor()

        # Detection configuration
        detection_config = self.config.get_section('ml').get('detection', {})
        self.confidence_threshold = detection_config.get('confidence_threshold', 0.7)
        self.ensemble_voting = detection_config.get('ensemble_voting', 'majority')

        # Model directory for loading pre-trained models
        self.model_dir = self.config.get('ml.model_directory', 'data/models')

        # Detection state
        self.models: Dict[str, Any] = {}
        self.model_metadata: Dict[str, Dict[str, Any]] = {}
        self.is_initialized = False

        # Statistics tracking
        self.detection_history: deque = deque(maxlen=10000)
        self.statistics = AnomalyStatistics(
            total_samples=0,
            anomaly_count=0,
            normal_count=0,
            anomaly_rate=0.0,
            avg_confidence=0.0,
            avg_anomaly_score=0.0,
            model_usage_stats={},
            detection_latency=0.0
        )

        # Load models if available
        self._load_models()

    def _load_models(self) -> bool:
        """Load pre-trained models for anomaly detection"""
        loaded_models = 0

        # Try to load models from ModelTrainer
        if self.model_trainer and hasattr(self.model_trainer, 'models'):
            self.models = self.model_trainer.models.copy()
            logger.info(f"Loaded {len(self.models)} models from ModelTrainer")
            loaded_models = len(self.models)
        else:
            # Load models directly from files
            model_files = {
                'random_forest': 'random_forest.pkl',
                'isolation_forest': 'isolation_forest.pkl',
                'one_class_svm': 'one_class_svm.pkl',
                'svm': 'svm.pkl',
                'logistic_regression': 'logistic_regression.pkl'
            }

            for model_name, filename in model_files.items():
                model_path = os.path.join(self.model_dir, filename)
                if os.path.exists(model_path):
                    try:
                        self.models[model_name] = joblib.load(model_path)
                        loaded_models += 1
                        logger.info(f"Loaded {model_name} model from {model_path}")
                    except Exception as e:
                        logger.error(f"Error loading {model_name}: {e}")

        # Load model metadata
        metadata_path = os.path.join(self.model_dir, 'training_metadata.json')
        if os.path.exists(metadata_path):
            try:
                import json
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                self.model_metadata = metadata.get('model_performances', {})
                logger.info("Loaded model metadata")
            except Exception as e:
                logger.error(f"Error loading model metadata: {e}")

        self.is_initialized = loaded_models > 0
        logger.info(f"Anomaly detector initialized with {loaded_models} models")

        return self.is_initialized

    def detect_flow_anomaly(self, flow_features: FlowFeatures) -> DetectionResult:
        """
        Detect anomalies in flow features

        Args:
            flow_features: FlowFeatures object to analyze

        Returns:
            DetectionResult with anomaly information
        """
        start_time = time.time()

        if not self.is_initialized:
            # Return default result if models not loaded
            return DetectionResult(
                timestamp=flow_features.start_time,
                is_anomaly=False,
                anomaly_score=0.0,
                confidence=0.0,
                model_predictions={},
                detection_method="no_models",
                metadata={"error": "No models loaded"}
            )

        try:
            # Extract features
            feature_vector = self.feature_extractor.transform_single_sample(flow_features)

            # Get model predictions
            model_predictions = self._get_model_predictions(feature_vector)

            # Ensemble voting
            is_anomaly, confidence, anomaly_score = self._ensemble_voting(model_predictions)

            # Create detection result
            result = DetectionResult(
                timestamp=flow_features.start_time,
                is_anomaly=is_anomaly,
                anomaly_score=anomaly_score,
                confidence=confidence,
                model_predictions=model_predictions,
                detection_method="ensemble",
                feature_vector=feature_vector,
                metadata={
                    "flow_key": flow_features.flow_key,
                    "protocol": flow_features.protocol,
                    "packet_count": flow_features.packet_count,
                    "duration": flow_features.duration
                }
            )

            # Update statistics
            self._update_statistics(result, time.time() - start_time)

            return result

        except Exception as e:
            logger.error(f"Error detecting flow anomaly: {e}")
            return DetectionResult(
                timestamp=flow_features.start_time,
                is_anomaly=False,
                anomaly_score=0.0,
                confidence=0.0,
                model_predictions={},
                detection_method="error",
                metadata={"error": str(e)}
            )

    def detect_window_anomaly(self, window_features: WindowFeatures) -> DetectionResult:
        """
        Detect anomalies in window features

        Args:
            window_features: WindowFeatures object to analyze

        Returns:
            DetectionResult with anomaly information
        """
        start_time = time.time()

        if not self.is_initialized:
            return DetectionResult(
                timestamp=window_features.window_start,
                is_anomaly=False,
                anomaly_score=0.0,
                confidence=0.0,
                model_predictions={},
                detection_method="no_models",
                metadata={"error": "No models loaded"}
            )

        try:
            # Convert WindowFeatures to feature vector
            feature_vector = self._window_features_to_vector(window_features)

            # Get model predictions
            model_predictions = self._get_model_predictions(feature_vector)

            # Ensemble voting
            is_anomaly, confidence, anomaly_score = self._ensemble_voting(model_predictions)

            # Create detection result
            result = DetectionResult(
                timestamp=window_features.window_start,
                is_anomaly=is_anomaly,
                anomaly_score=anomaly_score,
                confidence=confidence,
                model_predictions=model_predictions,
                detection_method="ensemble_window",
                feature_vector=feature_vector,
                metadata={
                    "window_duration": window_features.window_duration,
                    "total_packets": window_features.total_packets,
                    "unique_sources": window_features.unique_sources,
                    "port_scan_score": window_features.port_scan_score,
                    "dos_score": window_features.dos_score
                }
            )

            # Update statistics
            self._update_statistics(result, time.time() - start_time)

            return result

        except Exception as e:
            logger.error(f"Error detecting window anomaly: {e}")
            return DetectionResult(
                timestamp=window_features.window_start,
                is_anomaly=False,
                anomaly_score=0.0,
                confidence=0.0,
                model_predictions={},
                detection_method="error",
                metadata={"error": str(e)}
            )

    def _get_model_predictions(self, feature_vector: np.ndarray) -> Dict[str, Dict[str, Any]]:
        """Get predictions from all available models"""
        predictions = {}

        for model_name, model in self.models.items():
            try:
                prediction_start = time.time()
                prediction = model.predict(feature_vector)[0]
                prediction_time = time.time() - prediction_start

                # Get confidence/probability if available
                confidence = 0.0
                if hasattr(model, 'predict_proba'):
                    try:
                        proba = model.predict_proba(feature_vector)[0]
                        confidence = np.max(proba)
                    except:
                        confidence = 0.5
                elif hasattr(model, 'decision_function'):
                    try:
                        decision = model.decision_function(feature_vector)[0]
                        confidence = 1.0 / (1.0 + np.exp(-decision))  # Sigmoid
                    except:
                        confidence = 0.5
                else:
                    confidence = 0.5

                # For anomaly detection models, convert -1/1 to 0/1
                if model_name in ['isolation_forest', 'one_class_svm']:
                    prediction = 1 if prediction == -1 else 0
                    confidence = 1.0 - confidence  # Invert for anomaly detection

                predictions[model_name] = {
                    'prediction': int(prediction),
                    'confidence': float(confidence),
                    'prediction_time': float(prediction_time),
                    'is_anomaly': bool(prediction == 1)
                }

                # Update model usage stats
                if model_name not in self.statistics.model_usage_stats:
                    self.statistics.model_usage_stats[model_name] = 0
                self.statistics.model_usage_stats[model_name] += 1

            except Exception as e:
                logger.warning(f"Error getting prediction from {model_name}: {e}")
                predictions[model_name] = {
                    'prediction': 0,
                    'confidence': 0.0,
                    'prediction_time': 0.0,
                    'is_anomaly': False,
                    'error': str(e)
                }

        return predictions

    def _ensemble_voting(self, model_predictions: Dict[str, Dict[str, Any]]) -> Tuple[bool, float, float]:
        """
        Perform ensemble voting to make final decision

        Args:
            model_predictions: Dictionary of model predictions

        Returns:
            Tuple of (is_anomaly, confidence, anomaly_score)
        """
        if not model_predictions:
            return False, 0.0, 0.0

        if self.ensemble_voting == 'majority':
            return self._majority_voting(model_predictions)
        elif self.ensemble_voting == 'weighted':
            return self._weighted_voting(model_predictions)
        elif self.ensemble_voting == 'consensus':
            return self._consensus_voting(model_predictions)
        else:
            return self._majority_voting(model_predictions)

    def _majority_voting(self, model_predictions: Dict[str, Dict[str, Any]]) -> Tuple[bool, float, float]:
        """Majority voting ensemble"""
        anomaly_votes = sum(1 for pred in model_predictions.values() if pred.get('is_anomaly', False))
        total_votes = len(model_predictions)

        if total_votes == 0:
            return False, 0.0, 0.0

        is_anomaly = anomaly_votes > total_votes / 2
        confidence = anomaly_votes / total_votes
        anomaly_score = confidence

        return is_anomaly, confidence, anomaly_score

    def _weighted_voting(self, model_predictions: Dict[str, Dict[str, Any]]) -> Tuple[bool, float, float]:
        """Weighted voting based on model performance"""
        total_weight = 0.0
        anomaly_weight = 0.0

        for model_name, pred in model_predictions.items():
            # Get model performance weight (using F1-score if available)
            weight = 1.0  # Default weight
            if model_name in self.model_metadata:
                f1_score = self.model_metadata[model_name].get('f1_score', 1.0)
                weight = f1_score

            total_weight += weight
            if pred.get('is_anomaly', False):
                anomaly_weight += weight

        if total_weight == 0:
            return False, 0.0, 0.0

        confidence = anomaly_weight / total_weight
        is_anomaly = confidence > self.confidence_threshold
        anomaly_score = confidence

        return is_anomaly, confidence, anomaly_score

    def _consensus_voting(self, model_predictions: Dict[str, Dict[str, Any]]) -> Tuple[bool, float, float]:
        """Consensus voting (all models must agree)"""
        anomaly_votes = sum(1 for pred in model_predictions.values() if pred.get('is_anomaly', False))
        total_votes = len(model_predictions)

        if total_votes == 0:
            return False, 0.0, 0.0

        # All models must agree for anomaly
        is_anomaly = anomaly_votes == total_votes
        confidence = 1.0 if anomaly_votes == total_votes or anomaly_votes == 0 else 0.0
        anomaly_score = anomaly_votes / total_votes

        return is_anomaly, confidence, anomaly_score

    def _window_features_to_vector(self, window_features: WindowFeatures) -> np.ndarray:
        """Convert WindowFeatures to feature vector"""
        features = [
            # Aggregate traffic features
            float(window_features.total_packets),
            float(window_features.total_bytes),
            float(window_features.unique_sources),
            float(window_features.unique_destinations),
            float(window_features.unique_ports),

            # Traffic patterns
            float(window_features.new_flows_per_second),
            float(window_features.avg_flow_duration),
            float(window_features.flow_diversity),

            # Anomaly scores
            float(window_features.port_scan_score),
            float(window_features.dos_score),
            float(window_features.data_exfiltration_score),
            float(window_features.unusual_protocol_score),

            # Protocol ratios
            float(window_features.protocol_ratios.get('TCP', 0.0)),
            float(window_features.protocol_ratios.get('UDP', 0.0)),
            float(window_features.protocol_ratios.get('ICMP', 0.0)),
        ]

        return np.array(features).reshape(1, -1)

    def _update_statistics(self, result: DetectionResult, detection_latency: float):
        """Update detection statistics"""
        self.detection_history.append(result)

        # Update counters
        self.statistics.total_samples += 1
        if result.is_anomaly:
            self.statistics.anomaly_count += 1
        else:
            self.statistics.normal_count += 1

        # Update rates
        self.statistics.anomaly_rate = self.statistics.anomaly_count / self.statistics.total_samples

        # Update averages (running average)
        alpha = 0.1  # Learning rate for running average
        self.statistics.avg_confidence = (alpha * result.confidence +
                                         (1 - alpha) * self.statistics.avg_confidence)
        self.statistics.avg_anomaly_score = (alpha * result.anomaly_score +
                                            (1 - alpha) * self.statistics.avg_anomaly_score)
        self.statistics.detection_latency = (alpha * detection_latency +
                                            (1 - alpha) * self.statistics.detection_latency)

    def get_recent_detections(self, count: int = 100, anomaly_only: bool = False) -> List[DetectionResult]:
        """
        Get recent detection results

        Args:
            count: Number of results to return
            anomaly_only: Return only anomaly results

        Returns:
            List of DetectionResult objects
        """
        recent = list(self.detection_history)[-count:]

        if anomaly_only:
            recent = [r for r in recent if r.is_anomaly]

        return recent

    def get_anomaly_trends(self, time_window: float = 3600.0) -> Dict[str, Any]:
        """
        Get anomaly detection trends over time window

        Args:
            time_window: Time window in seconds

        Returns:
            Dictionary with trend information
        """
        current_time = time.time()
        window_start = current_time - time_window

        # Filter detections within time window
        window_detections = [
            d for d in self.detection_history
            if d.timestamp >= window_start
        ]

        if not window_detections:
            return {
                "time_window": time_window,
                "total_detections": 0,
                "anomaly_count": 0,
                "anomaly_rate": 0.0,
                "hourly_rate": 0.0
            }

        anomaly_count = sum(1 for d in window_detections if d.is_anomaly)
        anomaly_rate = anomaly_count / len(window_detections)
        hourly_rate = (anomaly_count / time_window) * 3600.0  # Anomalies per hour

        # Calculate trend direction (last 15 minutes vs previous 15 minutes)
        mid_time = current_time - (time_window / 2)
        first_half = [d for d in window_detections if d.timestamp < mid_time]
        second_half = [d for d in window_detections if d.timestamp >= mid_time]

        first_anomaly_rate = sum(1 for d in first_half if d.is_anomaly) / len(first_half) if first_half else 0
        second_anomaly_rate = sum(1 for d in second_half if d.is_anomaly) / len(second_half) if second_half else 0

        trend = "stable"
        if second_anomaly_rate > first_anomaly_rate * 1.2:
            trend = "increasing"
        elif second_anomaly_rate < first_anomaly_rate * 0.8:
            trend = "decreasing"

        return {
            "time_window": time_window,
            "total_detections": len(window_detections),
            "anomaly_count": anomaly_count,
            "anomaly_rate": anomaly_rate,
            "hourly_rate": hourly_rate,
            "trend": trend,
            "first_half_rate": first_anomaly_rate,
            "second_half_rate": second_anomaly_rate,
            "avg_confidence": np.mean([d.confidence for d in window_detections]),
            "avg_anomaly_score": np.mean([d.anomaly_score for d in window_detections if d.is_anomaly])
        }

    def get_model_performance_summary(self) -> Dict[str, Any]:
        """Get summary of model performance and usage"""
        summary = {
            "available_models": list(self.models.keys()),
            "model_usage_stats": self.statistics.model_usage_stats.copy(),
            "model_metadata": self.model_metadata.copy()
        }

        # Calculate model accuracy from recent detections
        if self.detection_history:
            model_accuracy = {}
            for model_name in self.models.keys():
                model_predictions = []
                actual_anomalies = []

                for detection in self.detection_history:
                    if model_name in detection.model_predictions:
                        model_predictions.append(detection.model_predictions[model_name]['is_anomaly'])
                        actual_anomalies.append(detection.is_anomaly)

                if model_predictions and actual_anomalies:
                    accuracy = sum(1 for p, a in zip(model_predictions, actual_anomalies) if p == a) / len(model_predictions)
                    model_accuracy[model_name] = accuracy

            summary["recent_accuracy"] = model_accuracy

        return summary

    def reset_statistics(self):
        """Reset detection statistics"""
        self.detection_history.clear()
        self.statistics = AnomalyStatistics(
            total_samples=0,
            anomaly_count=0,
            normal_count=0,
            anomaly_rate=0.0,
            avg_confidence=0.0,
            avg_anomaly_score=0.0,
            model_usage_stats={},
            detection_latency=0.0
        )
        logger.info("Detection statistics reset")

    def update_configuration(self, new_config: Dict[str, Any]):
        """Update detector configuration"""
        if 'confidence_threshold' in new_config:
            self.confidence_threshold = new_config['confidence_threshold']
        if 'ensemble_voting' in new_config:
            self.ensemble_voting = new_config['ensemble_voting']

        logger.info(f"Updated configuration: {new_config}")

    def export_detection_log(self, output_path: str, time_range: Optional[Tuple[float, float]] = None):
        """
        Export detection log to CSV file

        Args:
            output_path: Path to save CSV file
            time_range: Optional tuple of (start_time, end_time) to filter results
        """
        try:
            # Filter detections by time range if specified
            if time_range:
                start_time, end_time = time_range
                filtered_detections = [
                    d for d in self.detection_history
                    if start_time <= d.timestamp <= end_time
                ]
            else:
                filtered_detections = list(self.detection_history)

            # Convert to DataFrame
            data = []
            for detection in filtered_detections:
                row = {
                    'timestamp': datetime.fromtimestamp(detection.timestamp).isoformat(),
                    'is_anomaly': detection.is_anomaly,
                    'anomaly_score': detection.anomaly_score,
                    'confidence': detection.confidence,
                    'detection_method': detection.detection_method
                }

                # Add model predictions
                for model_name, pred in detection.model_predictions.items():
                    row[f'{model_name}_prediction'] = pred.get('prediction', 0)
                    row[f'{model_name}_confidence'] = pred.get('confidence', 0.0)

                # Add metadata
                if detection.metadata:
                    for key, value in detection.metadata.items():
                        row[f'meta_{key}'] = value

                data.append(row)

            df = pd.DataFrame(data)
            df.to_csv(output_path, index=False)
            logger.info(f"Exported {len(df)} detection records to {output_path}")

        except Exception as e:
            logger.error(f"Error exporting detection log: {e}")

    def get_detector_status(self) -> Dict[str, Any]:
        """Get current detector status"""
        return {
            "is_initialized": self.is_initialized,
            "available_models": list(self.models.keys()),
            "confidence_threshold": self.confidence_threshold,
            "ensemble_voting": self.ensemble_voting,
            "total_detections": len(self.detection_history),
            "current_statistics": asdict(self.statistics),
            "model_directory": self.model_dir
        }


# Global anomaly detector instance
_anomaly_detector_instance = None

def get_anomaly_detector(model_trainer: Optional[ModelTrainer] = None) -> AnomalyDetector:
    """Get or create the global anomaly detector instance"""
    global _anomaly_detector_instance
    if _anomaly_detector_instance is None:
        _anomaly_detector_instance = AnomalyDetector(model_trainer)
    return _anomaly_detector_instance

def cleanup_anomaly_detector():
    """Cleanup the global anomaly detector instance"""
    global _anomaly_detector_instance
    _anomaly_detector_instance = None