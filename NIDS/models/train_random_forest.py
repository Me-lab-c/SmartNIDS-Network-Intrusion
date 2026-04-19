import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

# Column names
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

# Load dataset
data = pd.read_csv("dataset/KDDTrain+.txt", names=columns)

# Clean
data.drop("difficulty", axis=1, inplace=True)
data["label"] = data["label"].apply(lambda x: 0 if x == "normal" else 1)

# Encode categorical
for col in ["protocol_type", "service", "flag"]:
    data[col] = LabelEncoder().fit_transform(data[col])

# Split
X = data.drop("label", axis=1)
y = data["label"]

scaler = StandardScaler()
X = scaler.fit_transform(X)
joblib.dump(scaler, "models/scaler.pkl")


X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Train Random Forest
rf_model = RandomForestClassifier(
    n_estimators=150,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)

rf_model.fit(X_train, y_train)

# Save model
joblib.dump(rf_model, "models/random_forest_nids.pkl")

print("✅ Random Forest model trained and saved successfully!")
