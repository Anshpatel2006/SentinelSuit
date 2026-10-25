"""
SentinelIDS Machine Learning Training & Model Serialization Script
Trains Random Forest model with StandardScaler and exports to .joblib
"""
import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from app.config import settings

def train_and_export():
    print("[*] Generating training flow dataset for SentinelIDS...")
    np.random.seed(42)
    n_samples = 1000
    n_features = 29
    
    # Generate balanced synthetic flow features for 5 classes
    X_list = []
    y_list = []
    
    # 0: BENIGN
    benign = np.random.normal(loc=10.0, scale=3.0, size=(n_samples, n_features))
    benign = np.clip(benign, 0, None)
    X_list.append(benign)
    y_list.extend([0] * n_samples)
    
    # 1: DoS (High rates, short IAT, huge packet volume)
    dos = np.random.normal(loc=80.0, scale=15.0, size=(n_samples, n_features))
    dos = np.clip(dos, 0, None)
    X_list.append(dos)
    y_list.extend([1] * n_samples)
    
    # 2: PortScan (Fast single packet sweeps, syn only)
    scan = np.random.normal(loc=35.0, scale=8.0, size=(n_samples, n_features))
    scan = np.clip(scan, 0, None)
    X_list.append(scan)
    y_list.extend([2] * n_samples)

    # 3: BruteForce (Port 22/21 periodic attempts)
    brute = np.random.normal(loc=55.0, scale=10.0, size=(n_samples, n_features))
    brute = np.clip(brute, 0, None)
    X_list.append(brute)
    y_list.extend([3] * n_samples)

    # 4: WebAttack (Anomalous payloads, SQL/XSS signatures)
    web = np.random.normal(loc=65.0, scale=12.0, size=(n_samples, n_features))
    web = np.clip(web, 0, None)
    X_list.append(web)
    y_list.extend([4] * n_samples)

    X = np.vstack(X_list)
    y = np.array(y_list)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("[*] Training RandomForestClassifier (n_estimators=100)...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
    clf.fit(X_train_scaled, y_train)

    y_pred = clf.predict(X_test_scaled)
    target_names = ["BENIGN", "DoS", "PortScan", "BruteForce", "WebAttack"]
    print("\n--- Evaluation Report ---")
    print(classification_report(y_test, y_pred, target_names=target_names))

    os.makedirs(settings.MODEL_PATH.parent, exist_ok=True)
    joblib.dump(clf, settings.MODEL_PATH)
    joblib.dump(scaler, settings.SCALER_PATH)
    print(f"[+] Model saved to: {settings.MODEL_PATH}")
    print(f"[+] Scaler saved to: {settings.SCALER_PATH}")

if __name__ == "__main__":
    train_and_export()
