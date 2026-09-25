import pickle
import numpy as np
import xgboost as xgb
import os

model_path = 'XGBoostClassifier.pickle.dat'

try:
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    print(f"Model loaded successfully. Type: {type(model)}")
    
    if hasattr(model, 'feature_importances_'):
        print(f"Number of features expected: {len(model.feature_importances_)}")
        print(f"Feature importances: {model.feature_importances_}")
    elif isinstance(model, xgb.Booster):
        print(f"Number of features expected: {model.num_features()}")
    else:
        # Try to infer from attributes
        print("Model doesn't have obvious feature count attribute.")
except Exception as e:
    print(f"Error loading model: {e}")
