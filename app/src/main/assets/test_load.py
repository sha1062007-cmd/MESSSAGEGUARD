import xgboost as xgb
import pickle
import numpy as np

def try_load():
    path = 'XGBoostClassifier.pickle.dat'
    print(f"Checking {path}...")
    
    # Try 1: Standard Pickle
    try:
        with open(path, 'rb') as f:
            model = pickle.load(f)
        print("Success: Loaded via pickle")
        return model
    except Exception as e:
        print(f"Fail: Pickle load error: {e}")

    # Try 2: XGBoost Booster load
    try:
        bst = xgb.Booster()
        bst.load_model(path)
        print("Success: Loaded via bst.load_model")
        return bst
    except Exception as e:
        print(f"Fail: bst.load_model error: {e}")

    return None

if __name__ == "__main__":
    model = try_load()
    if model:
        print(f"Model class: {type(model)}")
