import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# ---------------- LOAD MODELS ----------------
rf_model = joblib.load("models/random_forest_nids.pkl")
xgb_model = joblib.load("models/xgboost_nids.pkl")

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

# ---------------- LOAD TEST DATA ----------------
data = pd.read_csv("dataset/KDDTest+.txt", names=columns)

data.drop("difficulty", axis=1, inplace=True)
data["label"] = data["label"].apply(lambda x: 0 if x == "normal" else 1)

# Encode categorical
for col in ["protocol_type", "service", "flag"]:
    data[col] = LabelEncoder().fit_transform(data[col])

X = data.drop("label", axis=1)
y = data["label"]

# Scale
scaler = StandardScaler()
X = scaler.fit_transform(X)

# ---------------- HYBRID PREDICTION ----------------
# Predict all at once (FAST)
rf_preds = rf_model.predict(X)
xgb_preds = xgb_model.predict(X)

# Hybrid decision
hybrid_preds = []
for i in range(len(X)):
    if rf_preds[i] == xgb_preds[i]:
        hybrid_preds.append(rf_preds[i])
    else:
        hybrid_preds.append(xgb_preds[i])


# ---------------- EVALUATION ----------------
print("Hybrid Model Accuracy:", accuracy_score(y, hybrid_preds) * 100, "%")

print("\nConfusion Matrix:")
print(confusion_matrix(y, hybrid_preds))

print("\nClassification Report:")
print(classification_report(y, hybrid_preds))
