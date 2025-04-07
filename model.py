import os
import pandas as pd
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import warnings
warnings.filterwarnings("ignore")

DATASET_FOLDER = "MachineLearningCSV"
MODEL_FILENAME = "trained_model.pkl"

def load_and_merge_csv_files(folder):
    all_dataframes = []

    for filename in os.listdir(folder):
        if filename.endswith(".csv"):
            file_path = os.path.join(folder, filename)
            try:
                df = pd.read_csv(file_path, low_memory=False)
                df.columns = df.columns.str.strip()  # Clean column names

                if 'Label' in df.columns:
                    label_values = df['Label'].dropna().unique()
                    if len(label_values) > 1:
                        all_dataframes.append(df)
                        print(f"[+] Loaded: {filename} ({len(df)} rows, Labels: {label_values})")
                    else:
                        print(f"[!] Skipping {filename} (only one label: {label_values})")
                else:
                    print(f"[!] Skipping {filename} (missing 'Label' column)")
            except Exception as e:
                print(f"[!] Error loading {filename}: {e}")

    if not all_dataframes:
        raise ValueError("No valid CSV files with usable 'Label' column found.")

    return pd.concat(all_dataframes, ignore_index=True)

def preprocess_data(df):
    df = df.dropna(subset=['Label'])  # Drop rows where label is missing

    df.replace([np.inf, -np.inf], np.nan, inplace=True)  # Replace inf values with NaN
    df.fillna(0, inplace=True)  # Fill all remaining NaNs with 0

    X = df.drop('Label', axis=1)
    y = df['Label']

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y)

    # Keep only numeric features
    X = X.select_dtypes(include=['number'])

    # Optional: Clip extremely large values to prevent overflows
    X = X.clip(upper=1e6)

    if len(set(y)) < 2:
        raise ValueError("Need at least two classes in the dataset to train a classifier.")

    return train_test_split(X, y, test_size=0.2, random_state=42), X.columns.tolist(), label_encoder

def train_and_save_model(X_train, X_test, y_train, y_test, label_encoder):
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("[*] Classification Report:")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

    joblib.dump((clf, label_encoder), MODEL_FILENAME)
    print(f"[+] Model saved to {MODEL_FILENAME}")
    return clf

def get_ai_threat_prediction(data_row_dict):
    clf, label_encoder = joblib.load(MODEL_FILENAME)
    input_df = pd.DataFrame([data_row_dict])
    input_df = input_df[[col for col in clf.feature_names_in_ if col in input_df.columns]]
    input_df = input_df.fillna(0)

    prediction = clf.predict(input_df)[0]
    prediction_label = label_encoder.inverse_transform([prediction])[0]
    return prediction_label

if __name__ == "__main__":
    print("[*] Loading and preparing data...")
    full_df = load_and_merge_csv_files(DATASET_FOLDER)
    (X_train, X_test, y_train, y_test), features, label_encoder = preprocess_data(full_df)

    print(f"[*] Training model on {X_train.shape[0]} samples...")
    model = train_and_save_model(X_train, X_test, y_train, y_test, label_encoder)