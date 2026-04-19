# 🚨 SmartNIDS: Hybrid Network Intrusion Detection System

## 📌 Overview

SmartNIDS is an intelligent **Network Intrusion Detection System (NIDS)** that leverages machine learning models to detect, classify, and analyze network attacks in real time.

The system uses a **hybrid approach combining Random Forest and XGBoost** to improve detection accuracy and provide enhanced insights such as severity scoring and attack pattern recognition.

---

## 🎯 Features

* 🔍 Hybrid prediction using Random Forest & XGBoost
* ⚡ Real-time intrusion detection
* 📊 SOC-style dashboard visualization
* 🚨 Attack severity classification (Low, Medium, High)
* 🔁 Repeated attack pattern detection
* 📁 Log storage in MSSQL database
* 📈 Confidence score visualization
* 🌐 Web interface using Flask

---

## 🛠️ Tech Stack

* **Frontend:** HTML, CSS, JavaScript, Chart.js
* **Backend:** Flask (Python)
* **Machine Learning:**

  * Random Forest
  * XGBoost
* **Database:** Microsoft SQL Server (MSSQL)
* **Libraries:**

  * pandas
  * numpy
  * scikit-learn
  * xgboost
  * joblib



## 📊 Dataset

This project uses the **NSL-KDD dataset**, a benchmark dataset for network intrusion detection systems.

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/your-username/SmartNIDS.git
cd SmartNIDS
```

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Run the Application

```bash
python app.py
```

### 4️⃣ Open in Browser

```
http://127.0.0.1:5000/
```

## 🧠 How It Works

1. Input network traffic data (41 features from NSL-KDD)
2. Preprocessing & feature scaling
3. Predictions using:

   * Random Forest
   * XGBoost
4. Hybrid decision logic
5. Severity scoring & attack classification
6. Results displayed on dashboard

---


