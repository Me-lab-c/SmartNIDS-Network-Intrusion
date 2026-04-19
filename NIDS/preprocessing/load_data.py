import pandas as pd
import os
import joblib

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from xgboost import XGBClassifier

# ---------------- COLUMN NAMES ----------------
columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files",
    "num_outbound_cmds","is_host_login","is_guest_login",
    "count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "label","difficulty"
]

# ---------------- LOAD DATA ----------------
data = pd.read_csv(
    "dataset/KDDTrain+.txt",
    names=columns,
    header=None
)

# ---------------- CLEANING ----------------
data.drop("difficulty", axis=1, inplace=True)
data["label"] = data["label"].apply(lambda x: 0 if x == "normal" else 1)

# ---------------- ENCODING (SEPARATE ENCODERS) ----------------
protocol_encoder = LabelEncoder()
service_encoder = LabelEncoder()
flag_encoder = LabelEncoder()

data["protocol_type"] = protocol_encoder.fit_transform(data["protocol_type"])
data["service"] = service_encoder.fit_transform(data["service"])
data["flag"] = flag_encoder.fit_transform(data["flag"])

# ---------------- FEATURES & LABEL ----------------
X = data.drop("label", axis=1)
y = data["label"]

# ---------------- SCALING ----------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ---------------- TRAIN-TEST SPLIT ----------------
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ---------------- XGBOOST MODEL ----------------
xgb_model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1
)

xgb_model.fit(X_train, y_train)

# ---------------- EVALUATION ----------------
y_pred = xgb_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print("\nXGBoost Accuracy:", accuracy * 100, "%")
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# ---------------- SAVE MODELS & ENCODERS ----------------
os.makedirs("models", exist_ok=True)

joblib.dump(xgb_model, "models/xgboost_nids.pkl")
joblib.dump(scaler, "models/scaler.pkl")
joblib.dump(protocol_encoder, "models/protocol_encoder.pkl")
joblib.dump(service_encoder, "models/service_encoder.pkl")
joblib.dump(flag_encoder, "models/flag_encoder.pkl")

print("\nAll models and encoders saved successfully!")
print("\nDataset Shape:", data.shape)
print("\nFirst 5 rows:")
print(data.head())

print("\nLabel Distribution:")
print(data["label"].value_counts())

