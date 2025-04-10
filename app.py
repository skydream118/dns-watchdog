import streamlit as st
import pandas as pd
import xgboost as xgb
import time
import re
import matplotlib.pyplot as plt
import tempfile

st.set_page_config(page_title="DNS Watchdog", layout="wide")
st.title("🛡️ DNS Watchdog")
st.markdown("Real-time DNS filtering and threat detection using XGBoost `.json` model.")

# Upload model file (XGBoost JSON format)
json_model_file = st.sidebar.file_uploader("📦 Upload XGBoost Model (.json)", type=["json"])

# Upload DNS log CSV
uploaded_file = st.file_uploader("📂 Upload DNS Logs (CSV)", type="csv")

# Settings
st.sidebar.header("⚙️ Settings")
threshold = st.sidebar.slider("Confidence Threshold", 0.6, 0.99, 0.8)
simulate_stream = st.sidebar.checkbox("Simulate Real-Time Stream", True)
delay = st.sidebar.slider("Log Display Delay (seconds)", 0.1, 2.0, 0.5)

# Load model
def load_model(json_file):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        tmp.write(json_file.read())
        tmp_path = tmp.name
    model = xgb.Booster()
    model.load_model(tmp_path)
    return model

if json_model_file is not None:
    model = load_model(json_model_file)

    # Feature extraction
    def extract_features(domain):
        return [
            len(domain),
            sum(c.isdigit() for c in domain),
            len(re.findall(r'[^a-zA-Z0-9]', domain)),
            int('-' in domain),
            domain.count('.') + 1
        ]

    def predict_dns(row):
        domain = row['domain']
        features = extract_features(domain)
        dmatrix = xgb.DMatrix([features])
        confidence = model.predict(dmatrix)[0]
        verdict = "Malicious" if confidence > 0.8 else "Suspicious" if confidence > 0.5 else "Safe"
        return verdict, round(confidence, 2)

    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        if 'domain' not in df.columns:
            st.error("CSV must contain a `domain` column.")
        else:
            st.success(f"Loaded {len(df)} DNS log entries.")
            st.markdown("### 🔎 Scanning Results")

            results = []
            for _, row in df.iterrows():
                if simulate_stream:
                    time.sleep(delay)

                verdict, confidence = predict_dns(row)
                placeholder = st.empty()

                if confidence >= threshold:
                    if verdict == "Malicious":
                        placeholder.error(f"🚫 {verdict} | `{row['domain']}` | {confidence}")
                    elif verdict == "Suspicious":
                        placeholder.warning(f"⚠️ {verdict} | `{row['domain']}` | {confidence}")
                    else:
                        placeholder.success(f"✅ {verdict} | `{row['domain']}` | {confidence}")
                else:
                    placeholder.info(f"✅ Safe | `{row['domain']}` | Low confidence: {confidence}")

                results.append({
                    "Domain": row['domain'],
                    "Verdict": verdict,
                    "Confidence": confidence
                })

            result_df = pd.DataFrame(results)
            st.markdown("### 📊 Verdict Breakdown")
            st.bar_chart(result_df['Verdict'].value_counts())

            csv = result_df.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download Results", csv, "dns_results.csv")
    else:
        st.info("Upload a DNS log file to begin.")
else:
    st.warning("Please upload a valid `.json` XGBoost model in the sidebar.")
