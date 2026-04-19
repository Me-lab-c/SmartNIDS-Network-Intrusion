import dask.dataframe as dd

# Column names (same as ML part)
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

# Load NSL-KDD dataset using Dask
ddf = dd.read_csv(
    "dataset/KDDTrain+.txt",
    names=columns,
    header=None
)

print("NSL-KDD dataset loaded using Dask")

# Show structure (no full computation yet)
print(ddf.head())

# ---------------- BIG DATA ANALYSIS ----------------

# Convert labels to binary (for analysis)
ddf["label_binary"] = ddf["label"].apply(
    lambda x: "Normal" if x == "normal" else "Attack",
    meta=("label_binary", "object")
)

# Count normal vs attack traffic (Big Data computation)
label_distribution = ddf["label_binary"].value_counts().compute()

print("\nAttack vs Normal Distribution (Big Data Analysis):")
print(label_distribution)

# ---------------- PROTOCOL-WISE ATTACK ANALYSIS ----------------

# Filter only attack traffic
attack_data = ddf[ddf["label_binary"] == "Attack"]

# Count attacks per protocol (tcp, udp, icmp)
protocol_attack_counts = attack_data["protocol_type"].value_counts().compute()

print("\nProtocol-wise Attack Distribution (Big Data Analysis):")
print(protocol_attack_counts)

# ---------------- SERVICE-WISE ATTACK ANALYSIS ----------------

# Count attacks per service
service_attack_counts = attack_data["service"].value_counts().compute()

print("\nService-wise Attack Distribution (Big Data Analysis):")
print(service_attack_counts.head(10))  # top 10 attacked services

# ---------------- TRAFFIC STATISTICS ANALYSIS ----------------

# Average bytes sent and received for normal vs attack traffic
traffic_stats = ddf.groupby("label_binary")[["src_bytes", "dst_bytes"]].mean().compute()

print("\nAverage Traffic Statistics (Big Data Analysis):")
print(traffic_stats)
