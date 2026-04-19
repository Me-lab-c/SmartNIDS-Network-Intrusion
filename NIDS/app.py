from flask import Flask, render_template, request
import joblib
import numpy as np
import pyodbc

app = Flask(__name__)

# ================= LOAD MODELS =================
scaler = joblib.load("models/scaler.pkl")
rf_model = joblib.load("models/random_forest_nids.pkl")
xgb_model = joblib.load("models/xgboost_nids.pkl")

protocol_encoder = joblib.load("models/protocol_encoder.pkl")
service_encoder = joblib.load("models/service_encoder.pkl")
flag_encoder = joblib.load("models/flag_encoder.pkl")


# ================= DB CONNECTION =================
def get_db_connection():
    return pyodbc.connect(
        "DRIVER={ODBC Driver 17 for SQL Server};"
        "SERVER=MANVITHA\\SQLEXPRESS;"
        "DATABASE=NIDS_DB;"
        "Trusted_Connection=yes;"
    )


# ================= CONTINUOUS ATTACK CHECK =================
def check_continuous_attacks():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT TOP 7 prediction
        FROM prediction_logs
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    count = 0
    for row in rows:
        if "Attack" in row[0]:
            count += 1
        else:
            break

    return count


# ================= DATA FETCH FUNCTIONS =================

def fetch_recent_logs(limit=10):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(f"""
        SELECT TOP {limit} timestamp, prediction, model_used, severity, attack_pattern
        FROM prediction_logs
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows


def fetch_kpis():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            COUNT(*),
            SUM(CASE WHEN prediction LIKE 'Attack%' THEN 1 ELSE 0 END),
            SUM(CASE WHEN prediction LIKE 'Normal%' THEN 1 ELSE 0 END)
        FROM prediction_logs
    """)

    row = cursor.fetchone()
    conn.close()

    return {
        "total": row[0] or 0,
        "attacks": row[1] or 0,
        "normal": row[2] or 0
    }


def fetch_severity_distribution():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM prediction_logs
        WHERE severity IS NOT NULL
        GROUP BY severity
    """)

    data = cursor.fetchall()
    conn.close()

    result = {"Low": 0, "Medium": 0, "High": 0}

    for row in data:
        if row[0] in result:
            result[row[0]] = int(row[1])

    return result


def fetch_pattern_distribution():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT attack_pattern, COUNT(*)
        FROM prediction_logs
        WHERE prediction LIKE '%Attack%'
        GROUP BY attack_pattern
    """)

    data = cursor.fetchall()
    conn.close()

    result = {
        "Single Attack": 0,
        "Repeated Attack (3 Times)": 0,
        "Continuous Attack Pattern": 0,
        "Coordinated Intrusion Pattern": 0
    }

    for row in data:
        if row[0] in result:
            result[row[0]] = int(row[1])

    return result


def fetch_last_24h_attacks():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT DATEPART(HOUR, timestamp), COUNT(*)
        FROM prediction_logs
        WHERE timestamp >= DATEADD(HOUR, -24, GETDATE())
        AND prediction LIKE '%Attack%'
        GROUP BY DATEPART(HOUR, timestamp)
        ORDER BY DATEPART(HOUR, timestamp)
    """)

    data = cursor.fetchall()
    conn.close()

    hours = list(range(24))
    counts = [0] * 24

    for row in data:
        counts[row[0]] = int(row[1])

    return hours, counts


def fetch_risk_score():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            SUM(CASE 
                WHEN severity='High' THEN 3
                WHEN severity='Medium' THEN 2
                WHEN severity='Low' THEN 1
                ELSE 0 
            END)
        FROM prediction_logs
        WHERE timestamp >= DATEADD(HOUR, -1, GETDATE())
    """)

    score = cursor.fetchone()[0] or 0
    conn.close()

    return int(min(score * 5, 100))


def fetch_attack_logs():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT timestamp, prediction, severity, attack_pattern
        FROM prediction_logs
        WHERE prediction LIKE '%Attack%'
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows


# ================= DASHBOARD =================

@app.route("/", methods=["GET", "POST"])
def dashboard():

    prediction = severity = attack_pattern = None
    rf_conf = xgb_conf = None
    rf_pred_label = xgb_pred_label = None

    if request.method == "POST":
        input_data = request.form["features"]

        try:
            raw = input_data.split(",")

            if len(raw) != 41:
                prediction = "Error ❌: Enter exactly 41 values."
            else:
                # Encode categorical
                raw[1] = protocol_encoder.transform([raw[1]])[0]
                raw[2] = service_encoder.transform([raw[2]])[0]
                raw[3] = flag_encoder.transform([raw[3]])[0]

                values = list(map(float, raw))
                features = scaler.transform([values])

                # Model predictions
                rf_pred = rf_model.predict(features)[0]
                xgb_pred = xgb_model.predict(features)[0]

                rf_conf = float(round(max(rf_model.predict_proba(features)[0]) * 100, 2))
                xgb_conf = float(round(max(xgb_model.predict_proba(features)[0]) * 100, 2))

                rf_pred_label = "Attack" if rf_pred else "Normal"
                xgb_pred_label = "Attack" if xgb_pred else "Normal"

                final_pred = xgb_pred if rf_pred != xgb_pred else rf_pred
                prediction = "Attack 🚨" if final_pred else "Normal ✅"
                model_used = "Hybrid (RF + XGB)"

                # ---------- SEVERITY ----------
                if final_pred == 1:

                    traffic = values[22]
                    score = 0

                    if traffic >= 400:
                        score += 2
                    elif traffic >= 200:
                        score += 1

                    if xgb_conf >= 75:
                        score += 1

                    if score >= 3:
                        severity = "High"
                    elif score == 2:
                        severity = "Medium"
                    else:
                        severity = "Low"

                    # SAVE FIRST
                    conn = get_db_connection()
                    cursor = conn.cursor()

                    cursor.execute("""
                        INSERT INTO prediction_logs
                        (input_data, prediction, model_used, severity, attack_pattern)
                        VALUES (?, ?, ?, ?, ?)
                    """, input_data, prediction, model_used, severity, "Checking...")

                    conn.commit()
                    conn.close()

                    # CHECK CONTINUOUS
                    continuous_count = check_continuous_attacks()

                    if continuous_count >= 7:
                        attack_pattern = "Coordinated Intrusion Pattern"
                    elif continuous_count >= 5:
                        attack_pattern = "Continuous Attack Pattern"
                    elif continuous_count >= 3:
                        attack_pattern = "Repeated Attack (3 Times)"
                    else:
                        attack_pattern = "Single Attack"

                    # UPDATE PATTERN
                    conn = get_db_connection()
                    cursor = conn.cursor()

                    cursor.execute("""
                        UPDATE prediction_logs
                        SET attack_pattern = ?
                        WHERE id = (SELECT MAX(id) FROM prediction_logs)
                    """, attack_pattern)

                    conn.commit()
                    conn.close()

                else:
                    severity = "None"
                    attack_pattern = "Normal"

        except Exception as e:
            prediction = f"Error ❌: {str(e)}"

    return render_template(
        "dashboard.html",
        prediction=prediction,
        severity=severity,
        attack_pattern=attack_pattern,
        logs=fetch_recent_logs(),
        kpis=fetch_kpis(),
        rf_conf=rf_conf,
        xgb_conf=xgb_conf,
        rf_pred=rf_pred_label,
        xgb_pred=xgb_pred_label
    )


# ================= OTHER ROUTES =================

@app.route("/threats")
def threats():
    return render_template("threats.html", logs=fetch_attack_logs())


@app.route("/analytics")
def analytics():
    hours, attack_counts = fetch_last_24h_attacks()

    return render_template(
        "analytics.html",
        kpis=fetch_kpis(),
        severity_data=fetch_severity_distribution(),
        pattern_data=fetch_pattern_distribution(),
        hours=hours,
        attack_counts=attack_counts,
        risk_score=fetch_risk_score()
    )


@app.route("/logs")
def logs():
    return render_template("logs.html", logs=fetch_recent_logs(100))


if __name__ == "__main__":
    app.run(debug=True)
