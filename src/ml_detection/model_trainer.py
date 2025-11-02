"""
Machine Learning Model Trainer Module
Trains and persists ML models for network intrusion detection
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple, Optional, Union
from dataclasses import dataclass, asdict
import joblib
import os
import logging
import json
import time
from datetime import datetime
from pathlib import Path

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.svm import OneClassSVM, SVC
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score, StratifiedKFold
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        classification_report, confusion_matrix, roc_auc_score,
        precision_recall_curve, average_precision_score
    )
    from sklearn.preprocessing import LabelEncoder
    SCIKIT_LEARN_AVAILABLE = True
except ImportError:
    SCIKIT_LEARN_AVAILABLE = False
    logging.error("Scikit-learn is not available. Model training will be disabled.")

from .feature_extractor import MLFeatureExtractor, FeatureSet, FeatureExtractionResult
from ..config.settings import get_config

logger = logging.getLogger(__name__)


@dataclass
class ModelPerformance:
    """Model performance metrics"""
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: Optional[float] = None
    training_time: float = 0.0
    prediction_time: float = 0.0
    confusion_matrix: Optional[List[List[int]]] = None
    classification_report: Optional[Dict[str, Any]] = None
    cross_val_scores: Optional[List[float]] = None
    parameters: Optional[Dict[str, Any]] = None


@dataclass
class TrainingResult:
    """Result of model training process"""
    models: Dict[str, Any]
    performances: Dict[str, ModelPerformance]
    feature_extractor: MLFeatureExtractor
    training_data_info: Dict[str, Any]
    timestamp: datetime
    total_training_time: float


class ModelTrainer:
    """
    Trains and evaluates machine learning models for network intrusion detection
    """

    def __init__(self, model_dir: Optional[str] = None):
        """
        Initialize model trainer

        Args:
            model_dir: Directory to save trained models
        """
        if not SCIKIT_LEARN_AVAILABLE:
            raise ImportError("Scikit-learn is required for model training")

        self.config = get_config()
        self.model_dir = model_dir or self.config.get('ml.model_directory', 'data/models')
        self.feature_extractor = MLFeatureExtractor()

        # Training configuration
        training_config = self.config.get_section('ml').get('training', {})
        self.test_size = training_config.get('test_size', 0.2)
        self.random_state = training_config.get('random_state', 42)
        self.cv_folds = training_config.get('cross_validation_folds', 5)

        # Model configurations
        self.model_configs = self.config.get_section('ml').get('models', {})

        # Initialize models
        self.models: Dict[str, Any] = {}
        self.performances: Dict[str, ModelPerformance] = {}
        self._initialize_models()

        # Ensure model directory exists
        os.makedirs(self.model_dir, exist_ok=True)

    def _initialize_models(self):
        """Initialize machine learning models based on configuration"""
        # Random Forest
        if self.model_configs.get('random_forest', {}).get('enabled', True):
            rf_config = self.model_configs.get('random_forest', {})
            self.models['random_forest'] = RandomForestClassifier(
                n_estimators=rf_config.get('n_estimators', 100),
                max_depth=rf_config.get('max_depth', 10),
                random_state=rf_config.get('random_state', self.random_state),
                n_jobs=-1
            )

        # Isolation Forest (Anomaly Detection)
        if self.model_configs.get('isolation_forest', {}).get('enabled', True):
            iso_config = self.model_configs.get('isolation_forest', {})
            self.models['isolation_forest'] = IsolationForest(
                contamination=iso_config.get('contamination', 0.1),
                random_state=iso_config.get('random_state', self.random_state),
                n_jobs=-1
            )

        # One-Class SVM (Anomaly Detection)
        if self.model_configs.get('one_class_svm', {}).get('enabled', True):
            svm_config = self.model_configs.get('one_class_svm', {})
            self.models['one_class_svm'] = OneClassSVM(
                kernel=svm_config.get('kernel', 'rbf'),
                gamma=svm_config.get('gamma', 'scale'),
                nu=svm_config.get('nu', 0.1)
            )

        # SVM (Classification)
        if self.model_configs.get('svm', {}).get('enabled', False):
            svm_config = self.model_configs.get('svm', {})
            self.models['svm'] = SVC(
                kernel=svm_config.get('kernel', 'rbf'),
                probability=True,
                random_state=self.random_state
            )

        # Logistic Regression (Baseline)
        if self.model_configs.get('logistic_regression', {}).get('enabled', False):
            lr_config = self.model_configs.get('logistic_regression', {})
            self.models['logistic_regression'] = LogisticRegression(
                random_state=lr_config.get('random_state', self.random_state),
                max_iter=lr_config.get('max_iter', 1000)
            )

        logger.info(f"Initialized {len(self.models)} models: {list(self.models.keys())}")

    def train_from_features(self, features: np.ndarray, labels: np.ndarray,
                          feature_names: List[str]) -> TrainingResult:
        """
        Train models from pre-extracted features

        Args:
            features: Feature matrix (n_samples, n_features)
            labels: Target labels
            feature_names: List of feature names

        Returns:
            TrainingResult with trained models and performance metrics
        """
        start_time = time.time()

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=labels if len(np.unique(labels)) > 1 else None
        )

        # Prepare training data info
        training_data_info = {
            'total_samples': len(features),
            'training_samples': len(X_train),
            'test_samples': len(X_test),
            'feature_count': features.shape[1],
            'feature_names': feature_names,
            'class_distribution': dict(zip(*np.unique(labels, return_counts=True))),
            'training_timestamp': datetime.now().isoformat()
        }

        # Train models
        logger.info(f"Training {len(self.models)} models on {len(X_train)} samples...")
        trained_models = {}
        model_performances = {}

        for model_name, model in self.models.items():
            try:
                # Train model
                performance = self._train_single_model(
                    model, model_name, X_train, X_test, y_train, y_test
                )

                if performance:
                    trained_models[model_name] = model
                    model_performances[model_name] = performance
                    logger.info(f"{model_name}: Accuracy={performance.accuracy:.3f}, F1={performance.f1_score:.3f}")

            except Exception as e:
                logger.error(f"Error training {model_name}: {e}")

        total_training_time = time.time() - start_time

        # Save models and feature extractor
        self._save_models(trained_models, feature_names)
        self.feature_extractor.save_models(self.model_dir)

        # Save training metadata
        self._save_training_metadata(training_data_info, model_performances, total_training_time)

        result = TrainingResult(
            models=trained_models,
            performances=model_performances,
            feature_extractor=self.feature_extractor,
            training_data_info=training_data_info,
            timestamp=datetime.now(),
            total_training_time=total_training_time
        )

        logger.info(f"Training completed in {total_training_time:.2f} seconds")
        return result

    def _train_single_model(self, model: Any, model_name: str,
                          X_train: np.ndarray, X_test: np.ndarray,
                          y_train: np.ndarray, y_test: np.ndarray) -> Optional[ModelPerformance]:
        """
        Train a single model and evaluate its performance

        Args:
            model: Scikit-learn model instance
            model_name: Name of the model
            X_train: Training features
            X_test: Test features
            y_train: Training labels
            y_test: Test labels

        Returns:
            ModelPerformance object or None if training failed
        """
        training_start = time.time()

        try:
            # Handle anomaly detection models differently
            if model_name in ['isolation_forest', 'one_class_svm']:
                return self._train_anomaly_detection_model(
                    model, model_name, X_train, X_test, y_train, y_test
                )

            # Train classification model
            model.fit(X_train, y_train)
            training_time = time.time() - training_start

            # Make predictions
            prediction_start = time.time()
            y_pred = model.predict(X_test)
            prediction_time = time.time() - prediction_start

            # Get prediction probabilities if available
            y_pred_proba = None
            if hasattr(model, 'predict_proba'):
                y_pred_proba = model.predict_proba(X_test)

            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
            recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)

            # Calculate AUC-ROC if binary classification and probabilities available
            auc_roc = None
            if y_pred_proba is not None and len(np.unique(y_test)) == 2:
                auc_roc = roc_auc_score(y_test, y_pred_proba[:, 1])

            # Cross-validation
            cv_scores = None
            try:
                cv = StratifiedKFold(n_splits=self.cv_folds, shuffle=True, random_state=self.random_state)
                cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring='f1_weighted')
            except Exception as e:
                logger.warning(f"Cross-validation failed for {model_name}: {e}")

            # Generate classification report
            class_report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

            # Generate confusion matrix
            conf_matrix = confusion_matrix(y_test, y_pred).tolist()

            # Get model parameters
            model_params = model.get_params()

            return ModelPerformance(
                model_name=model_name,
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_score=f1,
                auc_roc=auc_roc,
                training_time=training_time,
                prediction_time=prediction_time,
                confusion_matrix=conf_matrix,
                classification_report=class_report,
                cross_val_scores=cv_scores.tolist() if cv_scores is not None else None,
                parameters=model_params
            )

        except Exception as e:
            logger.error(f"Error training {model_name}: {e}")
            return None

    def _train_anomaly_detection_model(self, model: Any, model_name: str,
                                     X_train: np.ndarray, X_test: np.ndarray,
                                     y_train: np.ndarray, y_test: np.ndarray) -> Optional[ModelPerformance]:
        """
        Train an anomaly detection model and evaluate its performance

        Args:
            model: Anomaly detection model instance
            model_name: Name of the model
            X_train: Training features
            X_test: Test features
            y_train: Training labels
            y_test: Test labels

        Returns:
            ModelPerformance object or None if training failed
        """
        training_start = time.time()

        try:
            # For anomaly detection, we typically train on normal data only
            # Assume that class 0 represents normal traffic
            normal_indices = np.where(y_train == 0)[0]
            if len(normal_indices) == 0:
                # If no normal data, use all data
                X_normal = X_train
            else:
                X_normal = X_train[normal_indices]

            # Train model
            model.fit(X_normal)
            training_time = time.time() - training_start

            # Make predictions (-1 for anomalies, 1 for normal)
            prediction_start = time.time()
            y_pred = model.predict(X_test)
            prediction_time = time.time() - prediction_start

            # Convert to binary labels (0 for normal, 1 for anomaly)
            y_pred_binary = np.where(y_pred == -1, 1, 0)

            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred_binary)
            precision = precision_score(y_test, y_pred_binary, average='weighted', zero_division=0)
            recall = recall_score(y_test, y_pred_binary, average='weighted', zero_division=0)
            f1 = f1_score(y_test, y_pred_binary, average='weighted', zero_division=0)

            # Generate classification report
            class_report = classification_report(y_test, y_pred_binary, output_dict=True, zero_division=0)

            # Generate confusion matrix
            conf_matrix = confusion_matrix(y_test, y_pred_binary).tolist()

            # Get model parameters
            model_params = model.get_params()

            return ModelPerformance(
                model_name=model_name,
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_score=f1,
                training_time=training_time,
                prediction_time=prediction_time,
                confusion_matrix=conf_matrix,
                classification_report=class_report,
                parameters=model_params
            )

        except Exception as e:
            logger.error(f"Error training anomaly detection model {model_name}: {e}")
            return None

    def hyperparameter_tuning(self, features: np.ndarray, labels: np.ndarray,
                            model_name: str, param_grid: Dict[str, List[Any]]) -> Dict[str, Any]:
        """
        Perform hyperparameter tuning for a specific model

        Args:
            features: Feature matrix
            labels: Target labels
            model_name: Name of the model to tune
            param_grid: Parameter grid for GridSearchCV

        Returns:
            Dictionary with best parameters and scores
        """
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found")

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels,
            test_size=self.test_size,
            random_state=self.random_state
        )

        # Create GridSearchCV
        cv = StratifiedKFold(n_splits=self.cv_folds, shuffle=True, random_state=self.random_state)
        grid_search = GridSearchCV(
            self.models[model_name],
            param_grid,
            cv=cv,
            scoring='f1_weighted',
            n_jobs=-1,
            verbose=1
        )

        # Fit grid search
        logger.info(f"Starting hyperparameter tuning for {model_name}...")
        grid_search.fit(X_train, y_train)

        # Evaluate best model
        best_model = grid_search.best_estimator_
        y_pred = best_model.predict(X_test)

        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)

        # Update model with best parameters
        self.models[model_name] = best_model

        result = {
            'best_parameters': grid_search.best_params_,
            'best_score': grid_search.best_score_,
            'test_accuracy': accuracy,
            'test_f1_score': f1,
            'cv_results': grid_search.cv_results_
        }

        logger.info(f"Hyperparameter tuning completed for {model_name}")
        logger.info(f"Best parameters: {grid_search.best_params_}")
        logger.info(f"Best CV score: {grid_search.best_score_:.3f}")
        logger.info(f"Test accuracy: {accuracy:.3f}, Test F1: {f1:.3f}")

        return result

    def evaluate_models(self, features: np.ndarray, labels: np.ndarray) -> Dict[str, ModelPerformance]:
        """
        Evaluate all trained models on test data

        Args:
            features: Test features
            labels: Test labels

        Returns:
            Dictionary of model performances
        """
        performances = {}

        for model_name, model in self.models.items():
            try:
                # Make predictions
                prediction_start = time.time()
                y_pred = model.predict(features)
                prediction_time = time.time() - prediction_start

                # Handle anomaly detection models
                if model_name in ['isolation_forest', 'one_class_svm']:
                    y_pred_binary = np.where(y_pred == -1, 1, 0)
                else:
                    y_pred_binary = y_pred

                # Calculate metrics
                accuracy = accuracy_score(labels, y_pred_binary)
                precision = precision_score(labels, y_pred_binary, average='weighted', zero_division=0)
                recall = recall_score(labels, y_pred_binary, average='weighted', zero_division=0)
                f1 = f1_score(labels, y_pred_binary, average='weighted', zero_division=0)

                # Generate classification report
                class_report = classification_report(labels, y_pred_binary, output_dict=True, zero_division=0)

                performances[model_name] = ModelPerformance(
                    model_name=model_name,
                    accuracy=accuracy,
                    precision=precision,
                    recall=recall,
                    f1_score=f1,
                    prediction_time=prediction_time,
                    classification_report=class_report
                )

            except Exception as e:
                logger.error(f"Error evaluating {model_name}: {e}")

        return performances

    def save_models(self, model_dir: Optional[str] = None):
        """Save all trained models to disk"""
        save_dir = model_dir or self.model_dir
        os.makedirs(save_dir, exist_ok=True)

        for model_name, model in self.models.items():
            model_path = os.path.join(save_dir, f'{model_name}.pkl')
            try:
                joblib.dump(model, model_path)
                logger.info(f"Saved {model_name} model to {model_path}")
            except Exception as e:
                logger.error(f"Error saving {model_name} model: {e}")

    def _save_models(self, models: Dict[str, Any], feature_names: List[str]):
        """Save trained models and metadata"""
        for model_name, model in models.items():
            model_path = os.path.join(self.model_dir, f'{model_name}.pkl')
            try:
                joblib.dump(model, model_path)
                logger.info(f"Saved {model_name} model to {model_path}")
            except Exception as e:
                logger.error(f"Error saving {model_name} model: {e}")

        # Save feature names
        feature_names_path = os.path.join(self.model_dir, 'feature_names.json')
        try:
            with open(feature_names_path, 'w') as f:
                json.dump(feature_names, f)
        except Exception as e:
            logger.error(f"Error saving feature names: {e}")

    def _save_training_metadata(self, training_data_info: Dict[str, Any],
                              performances: Dict[str, ModelPerformance],
                              total_training_time: float):
        """Save training metadata"""
        metadata = {
            'training_data_info': training_data_info,
            'model_performances': {name: asdict(perf) for name, perf in performances.items()},
            'total_training_time': total_training_time,
            'timestamp': datetime.now().isoformat(),
            'config': {
                'test_size': self.test_size,
                'random_state': self.random_state,
                'cv_folds': self.cv_folds,
                'model_configs': self.model_configs
            }
        }

        metadata_path = os.path.join(self.model_dir, 'training_metadata.json')
        try:
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            logger.info(f"Saved training metadata to {metadata_path}")
        except Exception as e:
            logger.error(f"Error saving training metadata: {e}")

    def load_models(self, model_dir: Optional[str] = None) -> bool:
        """Load trained models from disk"""
        load_dir = model_dir or self.model_dir

        loaded_count = 0
        for model_name in self.models.keys():
            model_path = os.path.join(load_dir, f'{model_name}.pkl')
            if os.path.exists(model_path):
                try:
                    self.models[model_name] = joblib.load(model_path)
                    loaded_count += 1
                    logger.info(f"Loaded {model_name} model from {model_path}")
                except Exception as e:
                    logger.error(f"Error loading {model_name} model: {e}")
            else:
                logger.warning(f"Model file not found: {model_path}")

        # Load feature names
        feature_names_path = os.path.join(load_dir, 'feature_names.json')
        if os.path.exists(feature_names_path):
            try:
                with open(feature_names_path, 'r') as f:
                    feature_names = json.load(f)
                logger.info(f"Loaded {len(feature_names)} feature names")
            except Exception as e:
                logger.error(f"Error loading feature names: {e}")

        logger.info(f"Loaded {loaded_count}/{len(self.models)} models")
        return loaded_count > 0

    def get_best_model(self, metric: str = 'f1_score') -> Tuple[str, Any, ModelPerformance]:
        """
        Get the best performing model based on a metric

        Args:
            metric: Metric to use for comparison ('accuracy', 'precision', 'recall', 'f1_score')

        Returns:
            Tuple of (model_name, model, performance)
        """
        if not self.performances:
            raise ValueError("No trained models available for comparison")

        best_model_name = max(self.performances.keys(),
                            key=lambda name: getattr(self.performances[name], metric))

        return (best_model_name,
                self.models[best_model_name],
                self.performances[best_model_name])

    def get_model_summary(self) -> Dict[str, Any]:
        """Get summary of all trained models"""
        if not self.performances:
            return {"status": "No models trained yet"}

        summary = {
            "total_models": len(self.performances),
            "models": {}
        }

        for model_name, performance in self.performances.items():
            summary["models"][model_name] = {
                "accuracy": performance.accuracy,
                "precision": performance.precision,
                "recall": performance.recall,
                "f1_score": performance.f1_score,
                "training_time": performance.training_time,
                "prediction_time": performance.prediction_time
            }

        # Find best model for each metric
        metrics = ['accuracy', 'precision', 'recall', 'f1_score']
        for metric in metrics:
            best_model = max(self.performances.keys(),
                           key=lambda name: getattr(self.performances[name], metric))
            summary[f"best_{metric}"] = {
                "model": best_model,
                "score": getattr(self.performances[best_model], metric)
            }

        return summary

    def generate_training_report(self, output_path: Optional[str] = None) -> str:
        """Generate a detailed training report"""
        if not self.performances:
            return "No trained models available for report generation"

        report_lines = [
            "Network Intrusion Detection System - Training Report",
            "=" * 60,
            f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total models trained: {len(self.performances)}",
            ""
        ]

        # Model performances
        for model_name, performance in self.performances.items():
            report_lines.extend([
                f"Model: {model_name}",
                "-" * 30,
                f"Accuracy: {performance.accuracy:.4f}",
                f"Precision: {performance.precision:.4f}",
                f"Recall: {performance.recall:.4f}",
                f"F1-Score: {performance.f1_score:.4f}",
                f"Training Time: {performance.training_time:.2f}s",
                f"Prediction Time: {performance.prediction_time:.4f}s",
            ])

            if performance.auc_roc is not None:
                report_lines.append(f"AUC-ROC: {performance.auc_roc:.4f}")

            if performance.cross_val_scores:
                cv_mean = np.mean(performance.cross_val_scores)
                cv_std = np.std(performance.cross_val_scores)
                report_lines.extend([
                    f"Cross-Validation Score: {cv_mean:.4f} ± {cv_std:.4f}",
                ])

            report_lines.append("")

        # Best models
        report_lines.extend([
            "Best Models by Metric:",
            "-" * 20
        ])

        metrics = ['accuracy', 'precision', 'recall', 'f1_score']
        for metric in metrics:
            best_model = max(self.performances.keys(),
                           key=lambda name: getattr(self.performances[name], metric))
            best_score = getattr(self.performances[best_model], metric)
            report_lines.append(f"{metric.capitalize()}: {best_model} ({best_score:.4f})")

        report_text = "\n".join(report_lines)

        # Save report if path provided
        if output_path:
            try:
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(output_path, 'w') as f:
                    f.write(report_text)
                logger.info(f"Training report saved to {output_path}")
            except Exception as e:
                logger.error(f"Error saving training report: {e}")

        return report_text


# Global model trainer instance
_model_trainer_instance = None

def get_model_trainer() -> ModelTrainer:
    """Get or create the global model trainer instance"""
    global _model_trainer_instance
    if _model_trainer_instance is None:
        _model_trainer_instance = ModelTrainer()
    return _model_trainer_instance

def cleanup_model_trainer():
    """Cleanup the global model trainer instance"""
    global _model_trainer_instance
    _model_trainer_instance = None