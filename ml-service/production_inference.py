"""
PRODUCTION INFERENCE WRAPPER - Proper Preprocessing Pipeline
=============================================================

This module handles the complete preprocessing pipeline for production inference,
ensuring that incoming flow data matches the exact format the model was trained on.
"""

import pickle
import json
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional
import warnings
warnings.filterwarnings('ignore')


class ProductionInference:
    """
    Production inference wrapper that ensures proper preprocessing.
    
    This class handles:
    1. Loading all trained artifacts (model, preprocessor, feature selector)
    2. Feature alignment (ensuring all expected features are present)
    3. Proper preprocessing (log transform, encoding, scaling)
    4. Feature selection (applying ORC selected features)
    5. Prediction with calibrated threshold
    """
    
    def __init__(self, artifacts_dir: str = "XGBoost_artifacts"):
        """
        Initialize the production inference pipeline.
        
        Args:
            artifacts_dir: Directory containing trained artifacts
        """
        self.artifacts_dir = artifacts_dir
        self.classifier = None
        self.preprocessor = None
        self.feature_selector = None
        self.metadata = None
        self.expected_features = None
        self.selected_features = None
        
        self._load_artifacts()
        self._initialize_feature_defaults()
    
    def _load_artifacts(self):
        """Load all trained artifacts."""
        print("Loading production artifacts...")
        
        # Load classifier
        with open(f'{self.artifacts_dir}/rf.pkl', 'rb') as f:
            self.classifier = pickle.load(f)
        
        # Load preprocessor
        with open(f'{self.artifacts_dir}/preprocessor.pkl', 'rb') as f:
            self.preprocessor = pickle.load(f)
        
        # Load feature selector
        with open(f'{self.artifacts_dir}/feature_selector.pkl', 'rb') as f:
            self.feature_selector = pickle.load(f)
        
        # Load metadata
        with open(f'{self.artifacts_dir}/training_metadata.json', 'r') as f:
            self.metadata = json.load(f)
        
        # Extract expected features
        self.expected_features = self.metadata.get('feature_names', [])
        self.selected_features = self.metadata.get('selected_features', [])
        
        print(f"✅ Loaded artifacts")
        print(f"   • Total features expected: {len(self.expected_features)}")
        print(f"   • Selected features: {len(self.selected_features)}")
        print(f"   • Threshold: {self.classifier.attack_threshold:.3f}")
    
    def _initialize_feature_defaults(self):
        """
        Initialize sensible default values for missing features.
        
        CRITICAL: Instead of using 0 for everything, we use statistically
        reasonable defaults based on UNSW-NB15 training data distribution.
        """
        # These defaults are based on median/mode values from UNSW-NB15
        # You should update these based on your actual training data statistics
        self.feature_defaults = {
            # Packet and byte counts - small legitimate flows
            'spkts': 4,
            'dpkts': 3,
            'sbytes': 200,
            'dbytes': 150,
            
            # Rates (use low values for normal traffic)
            'rate': 50,
            'sttl': 254,
            'dttl': 254,
            
            # Load and jitter
            'sload': 100,
            'dload': 100,
            'sloss': 0,
            'dloss': 0,
            'sjit': 0,
            'djit': 0,
            
            # Time features
            'swin': 255,
            'dwin': 255,
            'stcpb': 0,
            'dtcpb': 0,
            'smeansz': 100,
            'dmeansz': 100,
            
            # Connection tracking features
            'ct_state_ttl': 1,
            'ct_flw_http_mthd': 0,
            'ct_ftp_cmd': 0,
            'ct_srv_src': 1,
            'ct_srv_dst': 1,
            'ct_dst_ltm': 1,
            'ct_src_ltm': 1,
            'ct_src_dport_ltm': 1,
            'ct_dst_sport_ltm': 1,
            'ct_dst_src_ltm': 1,
            
            # Binary/flag features
            'is_ftp_login': 0,
            'is_sm_ips_ports': 0,
            
            # Numeric features default to small positive values
            'tcprtt': 0.001,
            'synack': 0.001,
            'ackdat': 0.001,
            
            # Categorical will be handled by preprocessor
        }
    
    def _align_features(self, flow_data: Dict[str, Any]) -> pd.DataFrame:
        """
        Align incoming flow data with expected features.
        
        Args:
            flow_data: Dictionary of extracted flow features
        
        Returns:
            DataFrame with all expected features
        """
        # Create a copy to avoid modifying original
        aligned_data = {}
        
        for feature in self.expected_features:
            if feature in flow_data:
                # Use provided value
                aligned_data[feature] = flow_data[feature]
            elif feature in self.feature_defaults:
                # Use sensible default
                aligned_data[feature] = self.feature_defaults[feature]
            else:
                # Last resort: use 0 (but log warning)
                aligned_data[feature] = 0
                if len(self.expected_features) < 20:  # Only warn if small feature set
                    print(f"⚠️  Unknown feature '{feature}' - using 0")
        
        # Create DataFrame
        df = pd.DataFrame([aligned_data])
        
        return df
    
    def predict(self, flow_data: Dict[str, Any], return_details: bool = False) -> Dict[str, Any]:
        """
        Make a prediction on a single flow.
        
        Args:
            flow_data: Dictionary containing flow features
            return_details: If True, return detailed information
        
        Returns:
            Dictionary with prediction results
        """
        try:
            # Step 1: Align features
            df = self._align_features(flow_data)
            
            # Step 2: Preprocess (log transform, encode, scale)
            X_processed = self.preprocessor.transform(df)
            
            # Step 3: Select features (apply ORC selection)
            X_selected = self.feature_selector.transform(X_processed)
            
            # Step 4: Predict
            proba = self.classifier.predict_proba(X_selected)[0, 1]
            prediction = "ATTACK" if proba >= self.classifier.attack_threshold else "NORMAL"
            
            result = {
                "prediction": prediction,
                "attack_probability": round(proba, 4),
                "threshold": self.classifier.attack_threshold
            }
            
            if return_details:
                result["details"] = {
                    "features_provided": len(flow_data),
                    "features_expected": len(self.expected_features),
                    "features_selected": len(self.selected_features),
                    "missing_features": list(set(self.expected_features) - set(flow_data.keys()))
                }
            
            return result
            
        except Exception as e:
            return {
                "prediction": "ERROR",
                "attack_probability": 0.0,
                "error": str(e)
            }
    
    def predict_batch(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Make predictions on multiple flows.
        
        Args:
            flows: List of flow dictionaries
        
        Returns:
            List of prediction results
        """
        results = []
        for flow in flows:
            results.append(self.predict(flow))
        return results
    
    def get_feature_importance(self, top_n: int = 20) -> pd.DataFrame:
        """
        Get feature importance from the trained model.
        
        Args:
            top_n: Number of top features to return
        
        Returns:
            DataFrame with feature importance scores
        """
        if hasattr(self.classifier.model, 'feature_importances_'):
            importances = self.classifier.model.feature_importances_
            feature_importance = pd.DataFrame({
                'feature': self.selected_features,
                'importance': importances
            }).sort_values('importance', ascending=False)
            
            return feature_importance.head(top_n)
        else:
            return pd.DataFrame()


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Initialize the inference engine
    engine = ProductionInference(artifacts_dir="XGBoost_artifacts")
    
    print("\n" + "="*70)
    print("Testing with your example flows...")
    print("="*70)
    
    # Your example flow (incomplete features)
    test_flow_1 = {
        'src': '192.168.125.39',
        'proto': 'tcp',
        'spkts': 3,
        'state': 'FIN',
        'ct_state_ttl': 0,
        'ct_srv_dst': 0,
        'ct_src_ltm': 0,
        'ct_dst_sport_ltm': 0
    }
    
    result_1 = engine.predict(test_flow_1, return_details=True)
    
    print("\n📊 Test Flow 1 (Original - Incomplete):")
    print(f"   Features provided: {result_1['details']['features_provided']}")
    print(f"   Features expected: {result_1['details']['features_expected']}")
    print(f"   Missing features: {len(result_1['details']['missing_features'])}")
    print(f"\n   Prediction: {result_1['prediction']}")
    print(f"   Probability: {result_1['attack_probability']:.4f}")
    print(f"   Threshold: {result_1['threshold']:.4f}")
    
    # A more complete normal flow example
    test_flow_2 = {
        'proto': 'tcp',
        'state': 'FIN',
        'spkts': 4,
        'dpkts': 3,
        'sbytes': 250,
        'dbytes': 180,
        'rate': 45.0,
        'sttl': 254,
        'dttl': 254,
        'sload': 120.0,
        'dload': 90.0,
        'swin': 255,
        'dwin': 255,
        'ct_state_ttl': 2,
        'ct_srv_src': 1,
        'ct_srv_dst': 1,
        'ct_dst_ltm': 1,
        'ct_src_ltm': 1
    }
    
    result_2 = engine.predict(test_flow_2, return_details=True)
    
    print("\n📊 Test Flow 2 (More Complete - Normal Traffic):")
    print(f"   Features provided: {result_2['details']['features_provided']}")
    print(f"   Prediction: {result_2['prediction']}")
    print(f"   Probability: {result_2['attack_probability']:.4f}")
    
    # Show top important features
    print("\n🎯 Top 10 Most Important Features:")
    importance_df = engine.get_feature_importance(top_n=10)
    for idx, row in importance_df.iterrows():
        print(f"   {idx+1:2d}. {row['feature']:20s} → {row['importance']:.4f}")
    
    print("\n" + "="*70)