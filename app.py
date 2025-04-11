import streamlit as st
import pandas as pd
import time
import re
import matplotlib.pyplot as plt
import joblib
import tempfile
import numpy as np

st.set_page_config(page_title="DNS Watchdog", layout="wide")
st.title("🛡️ DNS Watchdog")
st.markdown("Real-time DNS filtering and threat detection using an XGBoost model (joblib format)")

# Sidebar controls
st.sidebar.header("⚙️ Settings")
threshold = st.sidebar.slider("Confidence Threshold", 0.6, 0.99, 0.8)
simulate_stream = st.sidebar.checkbox("Simulate Real-Time Stream", True)
delay = st.sidebar.slider("Log Display Delay (seconds)", 0.1, 2.0, 0.5)

# Upload joblib-saved model
uploaded_model = st.sidebar.file_uploader("📦 Upload XGBoost Model (.pkl/.json)", type=["pkl", "json"])

# Upload DNS logs
uploaded_file = st.file_uploader("📂 Upload DNS Logs (CSV with `domain` column)", type="csv")

# Load model from file-like object
def load_model(uploaded_file):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".model") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name
    model = joblib.load(tmp_path)
    return model

if uploaded_model is not None:
    model = load_model(uploaded_model)

    def extract_features(domain):
        return [
            len(domain),
            sum(c.isdigit() for c in domain),
            len(re.findall(r'[^a-zA-Z0-9]', domain)),
            int('-' in domain),
            domain.count('.') + 1
        ]

    def predict_dns(domain):
        features = extract_features(domain)
        features_array = np.array(features).reshape(1, -1)  # Ensure it's 2D
        prediction = model.predict(features_array)[0]
        confidence = max(model.predict_proba(features_array)[0])
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

                verdict, confidence = predict_dns(row['domain'])
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
            fig1, ax1 = plt.subplots()
            ax1.pie(result_df['Verdict'].value_counts(), labels=result_df['Verdict'].unique(), autopct='%1.1f%%', startangle=90)
            ax1.axis('equal')
            st.pyplot(fig1)

            csv = result_df.to_csv(index=False).encode("utf-8")
            st.download_button("⬇️ Download Results", csv, "dns_results.csv")
    else:
        st.info("Upload a DNS log file to begin.")
else:
    st.warning("Please upload your joblib-saved XGBoost model.")
