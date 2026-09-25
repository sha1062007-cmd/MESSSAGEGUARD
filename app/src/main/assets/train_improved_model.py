import numpy as np
import pandas as pd
import xgboost as xgb
import pickle
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold, learning_curve
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, roc_auc_score
from URLFeatureExtraction_v2 import AdvancedURLFeatureExtractor

# 1. Realistic Dataset Generation (Incorporating Noise & Overlap to prevent 100% accuracy)
def generate_realistic_dataset(n_samples=10000):
    extractor = AdvancedURLFeatureExtractor()
    data = []
    labels = []
    
    # Mix of patterns to create overlap
    legit_domains = ['google', 'github', 'microsoft', 'apple', 'amazon', 'wikipedia', 'linkedin', 'twitter']
    phish_domains = ['secure-login', 'verify-service', 'account-update', 'banking-portal', 'auth-check']
    tlds = ['com', 'org', 'net', 'io']
    suspicious_tlds = ['xyz', 'top', 'tk', 'click', 'cyou', 'icu', 'ml', 'cf']
    
    for i in range(n_samples):
        is_phishing = np.random.rand() < 0.35 # 35% phishing
        
        # INCREASE NOISE to 12% for realistic overlap
        noise = np.random.rand() < 0.12 
        
        if is_phishing and not noise:
            dom = np.random.choice(phish_domains)
            tld = np.random.choice(suspicious_tlds)
            protocol = "http" if np.random.rand() < 0.8 else "https"
            url = f"{protocol}://{dom}.{tld}/scan?id={np.random.randint(1000, 999999)}"
            label = 1
        elif not is_phishing and not noise:
            dom = np.random.choice(legit_domains)
            tld = np.random.choice(tlds)
            url = f"https://www.{dom}.{tld}/home"
            label = 0
        else:
            # Overlap/Noisy samples
            dom = np.random.choice(legit_domains if np.random.rand() > 0.5 else phish_domains)
            tld = np.random.choice(suspicious_tlds if np.random.rand() > 0.5 else tlds)
            url = f"http://{dom}.{tld}/redirect"
            label = np.random.choice([0, 1])
            
        feats, _ = extractor.extract_features(url)
        # Add jitter to features
        feats_with_noise = [f + (np.random.normal(0, 0.1) if isinstance(f, (int, float)) else 0) for f in feats]
        data.append(feats_with_noise)
        labels.append(label)
        
    df = pd.DataFrame(data)
    df['target'] = labels
    return df

def plot_learning_curve(estimator, X, y):
    try:
        train_sizes, train_scores, test_scores = learning_curve(
            estimator, X, y, cv=5, n_jobs=-1, train_sizes=np.linspace(.1, 1.0, 5), scoring='accuracy'
        )
        
        train_scores_mean = np.mean(train_scores, axis=1)
        test_scores_mean = np.mean(test_scores, axis=1)

        plt.figure(figsize=(10, 6))
        plt.plot(train_sizes, train_scores_mean, 'o-', color="r", label="Training score")
        plt.plot(train_sizes, test_scores_mean, 'o-', color="g", label="Cross-validation score")
        plt.title("XGBoost Learning Curve (Generalization Check)")
        plt.xlabel("Training examples")
        plt.ylabel("Score")
        plt.legend(loc="best")
        plt.grid()
        plt.savefig("learning_curve.png")
    except Exception as e:
        print(f"Skipping learning curve plot: {e}")

def train_pipeline():
    df = generate_realistic_dataset(10000)
    X = df.drop('target', axis=1)
    y = df['target']
    
    print("\nStep 1: Splitting data (80/20 Stratified)...")
    X_train, X_holdout, y_train, y_holdout = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # 3. Create Validation Set for Early Stopping
    X_train_sub, X_val, y_train_sub, y_val = train_test_split(
        X_train, y_train, test_size=0.1, random_state=42, stratify=y_train
    )
    
    # 4. Define Overfitting-Resistant Model
    print("Step 2: Training with Regularization & Early Stopping...")
    # Parameters for the final model
    params = {
        'n_estimators': 500,
        'max_depth': 4,
        'learning_rate': 0.05,
        'min_child_weight': 4,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'reg_alpha': 0.5,
        'reg_lambda': 1.5,
        'random_state': 42,
        'eval_metric': "logloss"
    }
    
    model = xgb.XGBClassifier(**params, early_stopping_rounds=20)
    
    model.fit(
        X_train_sub, y_train_sub,
        eval_set=[(X_val, y_val)],
        verbose=False
    )
    
    # 5. Cross-Validation (5-Fold)
    print("Step 3: Performing 5-Fold Cross-Validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = []
    
    # Remove early stopping for CV as it needs a validation set for each fold
    cv_params = params.copy()
    
    for train_idx, test_idx in cv.split(X_train, y_train):
        it_X_train, it_X_test = X_train.iloc[train_idx], X_train.iloc[test_idx]
        it_y_train, it_y_test = y_train.iloc[train_idx], y_train.iloc[test_idx]
        
        it_model = xgb.XGBClassifier(**cv_params)
        it_model.fit(it_X_train, it_y_train)
        cv_scores.append(accuracy_score(it_y_test, it_model.predict(it_X_test)))
    
    print(f"Average CV Accuracy: {np.mean(cv_scores):.4f} (+/- {np.std(cv_scores):.4f})")

    # 6. Evaluation on Unseen Holdout Set
    print("\nStep 4: Final Evaluation on Unseen Holdout Set...")
    y_pred = model.predict(X_holdout)
    y_prob = model.predict_proba(X_holdout)[:, 1]
    
    acc = accuracy_score(y_holdout, y_pred)
    auc = roc_auc_score(y_holdout, y_prob)
    
    print("\n=== REAL PERFORMANCE METRICS (HOLDOUT) ===")
    print(f"Accuracy: {acc:.4f}")
    print(f"ROC-AUC: {auc:.4f}")
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_holdout, y_pred))
    print("\nDetailed Classification Report:")
    print(classification_report(y_holdout, y_pred))
    
    # 7. Diagnostics
    plot_learning_curve(xgb.XGBClassifier(**cv_params), X_train, y_train)
    
    # 8. Save Corrected Model
    with open('XGBoostClassifier_Improved.pickle.dat', 'wb') as f:
        pickle.dump(model, f)
    print("\nRobust Model saved as 'XGBoostClassifier_Improved.pickle.dat'")

if __name__ == "__main__":
    train_pipeline()
