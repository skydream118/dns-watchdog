import streamlit as st
import pandas as pd
import numpy as np
import re
import time
import joblib
import tempfile
import matplotlib.pyplot as plt

# -------------------- Streamlit Config -------------------- #
st.set_page_config(page_title="DNS Watchdog", layout="wide")
st.title("🛡️ DNS Watchdog")
st.markdown("Real-time DNS filtering and threat detection with an XGBoost model")

# -------------------- Sidebar Controls -------------------- #
st.sidebar.header("⚙️ Settings")
threshold = st.sidebar.slider("Confidence Threshold", 0.6, 0.99, 0.8)
simulate_stream = st.sidebar.checkbox("Simulate Real-Time Stream", True)
delay = st.sidebar.slider("Log Display Delay (seconds)", 0.1, 2.0, 0.5)

# Upload model (joblib-saved .pkl or .json)
uploaded_model = st.sidebar.file_uploader("📦 Upload XGBoost Model (.pkl or .json)", type=["pkl", "json"])

# Upload CSV logs
uploaded_csv = st.file_uploader("📂 Upload DNS Logs (CSV with `domain` column)", type="csv")

# -------------------- Model Loader -------------------- #
def load_model(uploaded_file):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".model") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name
    return joblib.load(tmp_path)

# -------------------- Feature Extractor -------------------- #
def extract_features(domain):
    return [
        len(domain),                                # domain length
        sum(c.isdigit() for c in domain),           # digit count
        len(re.findall(r'[^a-zA-Z0-9]', domain)),   # special characters
        int('-' in domain),                         # has hyphen
    ]

# -------------------- Prediction Function -------------------- #
def predict_dns(domain):
    features = extract_features(domain)
    features_array = np.array([features], dtype=np.float32)  # Ensuring correct shape and dtype
    prediction = model.predict(features_array)[0]
    confidence = max(model.predict_proba(features_array)[0])
    verdict = "Malicious" if confidence > 0.8 else "Suspicious" if confidence > 0.5 else "Safe"
    return verdict, round(confidence, 2)

# -------------------- Main App Logic -------------------- #
if uploaded_model:
    try:
        model = load_model(uploaded_model)
        st.success("✅ Model loaded successfully!")

        if uploaded_csv:
            df = pd.read_csv(uploaded_csv)
            if 'domain' not in df.columns:
                st.error("❌ The CSV file must contain a `domain` column.")
            else:
                st.success(f"Loaded {len(df)} DNS log entries.")
                st.markdown("### 🔍 Scanning Results")

                results = []
                for _, row in df.iterrows():
                    domain = row['domain']
                    verdict, confidence = predict_dns(domain)

                    if simulate_stream:
                        time.sleep(delay)

                    placeholder = st.empty()
                    if confidence >= threshold:
                        if verdict == "Malicious":
                            placeholder.error(f"🚫 **{verdict}** | `{domain}` | Confidence: {confidence}")
                        elif verdict == "Suspicious":
                            placeholder.warning(f"⚠️ **{verdict}** | `{domain}` | Confidence: {confidence}")
                        else:
                            placeholder.success(f"✅ **{verdict}** | `{domain}` | Confidence: {confidence}")
                    else:
                        placeholder.info(f"✅ **Safe** | `{domain}` | Low Confidence: {confidence}")

                    results.append({
                        "Domain": domain,
                        "Verdict": verdict,
                        "Confidence": confidence
                    })

                # Show results
                result_df = pd.DataFrame(results)
                st.markdown("### 📊 Threat Summary")
                fig, ax = plt.subplots()
                verdict_counts = result_df['Verdict'].value_counts()
                ax.pie(verdict_counts, labels=verdict_counts.index, autopct='%1.1f%%', startangle=90)
                ax.axis('equal')
                st.pyplot(fig)

                # Export results
                csv_data = result_df.to_csv(index=False).encode("utf-8")
                st.download_button("⬇️ Download Results", data=csv_data, file_name="dns_scan_results.csv")

        else:
            st.info("📂 Please upload a DNS log CSV file to begin.")
    except Exception as e:
        st.error(f"❌ Failed to load model or run predictions: {e}")
else:
    st.warning("📦 Please upload a model file saved using `joblib.dump(model, 'model.pkl')`.")
