import pickle
import xgboost as xgb
import os

try:
    with open('XGBoostClassifier.pickle.dat', 'rb') as f:
        data = pickle.load(f)
    print(f"Data type: {type(data)}")
except Exception as e:
    print(f"Error: {e}")
