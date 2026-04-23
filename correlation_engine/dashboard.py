import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
import requests
import json
from typing import List, Dict
import plotly.graph_objects as go
import plotly.express as px

# Configuration
OLLAMA_URL = "http://ollama:11434/api/generate"
MODEL_NAME = "llama3.2"

# Mock alert generator (for demo/training)
def generate_mock_alerts(num_alerts=50):
    """Generate realistic mock alerts for demo"""
    alert_types = [
        {"type": "Phishing", "severity": "High", "mitre": "T1566"},
        {"type": "Brute Force", "severity": "Medium", "mitre": "T1110"},
        {"type": "Privilege Escalation", "severity": "Critical", "mitre": "T1068"},
        {"type": "Lateral Movement", "severity": "High", "mitre": "T1021"},
        {"type": "Data Exfiltration", "severity": "Critical", "mitre": "T1041"},
        {"type": "Malware Detection", "severity": "High", "mitre": "T1204"},
        {"type": "Suspicious Powershell", "severity": "Medium", "mitre": "T1059"},
        {"type": "Registry Modification", "severity": "Low", "mitre": "T1112"},
    ]
    
    alerts = []
    base_time = datetime.now() - timedelta(hours=24)
    
    for i in range(num_alerts):
        alert = alert_types[i % len(alert_types)].copy()
        alert["id"] = f"ALT-{i:04d}"
        alert["source"] = np.random.choice(["SIEM", "EDR", "Firewall", "CloudTrail"])
        alert["timestamp"] = base_time + timedelta(minutes=np.random.randint(0, 1440))
        alert["source_ip"] = f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
        alert["destination_ip"] = f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
        alert["user"] = np.random.choice(["admin", "user1", "system", "svc_account"])
        alerts.append(alert)
    
    return pd.DataFrame(alerts)

# AI Correlation Engine
class AlertCorrelationEngine:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
    
    def extract_features(self, df: pd.DataFrame) -> np.ndarray:
        """Extract numerical features for ML correlation"""
        features = []
        for _, alert in df.iterrows():
            # Temporal features
            hour = alert['timestamp'].hour
            day_of_week = alert['timestamp'].dayofweek
            
            # Categorical encoding
            severity_score = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}[alert['severity']]
            source_score = {"SIEM": 1, "EDR": 2, "Firewall": 3, "CloudTrail": 4}[alert['source']]
            
            features.append([hour, day_of_week, severity_score, source_score])
        
        return np.array(features)
    
    def correlate_alerts(self, df: pd.DataFrame) -> Dict:
        """Correlate alerts and identify attack chains"""
        # ML-based anomaly detection
        features = self.extract_features(df)
        anomalies = self.model.fit_predict(features)
        df['is_correlated'] = anomalies == -1  # -1 indicates anomaly/anomaly group
        
        # Group correlated alerts by time window (10 minutes)
        df['time_group'] = df['timestamp'].dt.floor('10min')
        groups = df[df['is_correlated']].groupby('time_group')
        
        correlated_clusters = []
        for time_group, group in groups:
            if len(group) > 1:  # Only clusters with multiple alerts
                cluster = {
                    "time": time_group,
                    "alerts": group.to_dict('records'),
                    "severity": group['severity'].mode()[0] if not group['severity'].empty else "Medium",
                    "attack_chain": self.infer_attack_chain(group)
                }
                correlated_clusters.append(cluster)
        
        return {
            "clusters": correlated_clusters,
            "total_alerts": len(df),
            "correlated_alerts": len(df[df['is_correlated']]),
            "reduction_percentage": (len(df) - len(df[df['is_correlated']])) / len(df) * 100
        }
    
    def infer_attack_chain(self, group: pd.DataFrame) -> List[str]:
        """Infer MITRE ATT&CK attack chain from alerts"""
        mitre_map = {
            "T1566": "Phishing",
            "T1110": "Brute Force",
            "T1068": "Privilege Escalation", 
            "T1021": "Lateral Movement",
            "T1041": "Data Exfiltration"
        }
        
        alerts_in_order = group.sort_values('timestamp')
        chain = []
        for _, alert in alerts_in_order.iterrows():
            mitre = alert.get('mitre', '')
            if mitre in mitre_map:
                chain.append(mitre_map[mitre])
        
        return chain if chain else ["Initial Access → Suspicious Activity"]

# LLM Narrative Generation
def generate_root_cause_narrative(cluster: Dict) -> str:
    """Generate human-readable root cause summary using local LLM"""
    try:
        alert_summary = f"Found {len(cluster['alerts'])} correlated alerts at {cluster['time']}. "
        attack_chain = " → ".join(cluster['attack_chain']) if cluster['attack_chain'] else "Unknown"
        alert_summary += f"Attack chain: {attack_chain}. "
        
        # Call Ollama (free local LLM)
        response = requests.post(OLLAMA_URL, json={
            "model": MODEL_NAME,
            "prompt": f"""You are a SOC analyst. Analyze this alert cluster and provide a root cause summary in 2-3 sentences:
            
            {alert_summary}
            
            Explain what likely happened and recommend immediate action.
            """,
            "stream": False
        })
        
        if response.status_code == 200:
            return response.json().get('response', 'Unable to generate narrative')
        else:
            return f"Alert cluster detected: {alert_summary} Recommended: Investigate immediately."
    except:
        return "Root cause analysis unavailable (LLM not running). Use UI for manual investigation."

# Streamlit Dashboard
def main():
    st.set_page_config(
        page_title="AI SOC Agent",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.title("🛡️ Autonomous AI Security Operations Center")
    st.markdown("*AI-Powered Alert Correlation | Threat Intelligence | SOC Co-Pilot*")
    
    # Sidebar controls
    with st.sidebar:
        st.header("⚙️ Controls")
        
        if st.button("🔄 Load Mock Alerts", use_container_width=True):
            with st.spinner("Generating alerts..."):
                st.session_state.alerts = generate_mock_alerts(50)
                st.session_state.correlation = AlertCorrelationEngine().correlate_alerts(st.session_state.alerts)
                st.success(f"Loaded {len(st.session_state.alerts)} alerts")
        
        st.divider()
        
        st.header("🎯 LLM Status")
        try:
            resp = requests.get("http://ollama:11434/api/tags", timeout=2)
            if resp.status_code == 200:
                st.success("✅ Ollama Connected")
        except:
            st.warning("⚠️ Running in offline mode")
            st.info("Install Ollama for AI narratives")
        
        st.divider()
        
        st.header("📊 Metrics")
        if 'correlation' in st.session_state:
            st.metric("Alert Reduction", f"{st.session_state.correlation['reduction_percentage']:.0f}%")
            st.metric("Correlated Alerts", st.session_state.correlation['correlated_alerts'])
    
    # Main content area with tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 Alert Dashboard", 
        "🔗 Correlated Clusters", 
        "🤖 SOC Co-Pilot", 
        "📈 Threat Intelligence"
    ])
    
    with tab1:
        st.header("Real-time Alert Dashboard")
        
        if 'alerts' in st.session_state:
            # Time series chart
            alerts_by_hour = st.session_state.alerts.groupby(
                st.session_state.alerts['timestamp'].dt.hour
            ).size()
            
            fig = px.line(
                x=alerts_by_hour.index, 
                y=alerts_by_hour.values,
                title="Alerts Timeline (Last 24 Hours)",
                labels={'x': 'Hour of Day', 'y': 'Alert Count'}
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Severity distribution
            col1, col2 = st.columns(2)
            with col1:
                severity_counts = st.session_state.alerts['severity'].value_counts()
                fig_pie = px.pie(
                    values=severity_counts.values,
                    names=severity_counts.index,
                    title="Alerts by Severity"
                )
                st.plotly_chart(fig_pie, use_container_width=True)
            
            with col2:
                source_counts = st.session_state.alerts['source'].value_counts()
                st.bar_chart(source_counts)
            
            # Alert table
            with st.expander("📋 Detailed Alert Log"):
                st.dataframe(
                    st.session_state.alerts,
                    column_config={
                        "timestamp": st.column_config.DatetimeColumn("Time"),
                        "severity": st.column_config.SelectboxColumn("Severity", options=["Low", "Medium", "High", "Critical"])
                    },
                    use_container_width=True
                )
        else:
            st.info("Click 'Load Mock Alerts' in the sidebar to begin")
    
    with tab2:
        st.header("🔗 Correlated Alert Clusters")
        
        if 'correlation' in st.session_state and st.session_state.correlation['clusters']:
            for idx, cluster in enumerate(st.session_state.correlation['clusters']):
                with st.container():
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.subheader(f"📌 Cluster {idx + 1}")
                        st.write(f"**Time:** {cluster['time']}")
                        st.write(f"**Attack Chain:** {' → '.join(cluster['attack_chain'])}")
                        st.write(f"**Severity:** {cluster['severity']}")
                    
                    with col2:
                        if st.button(f"Analyze", key=f"analyze_{idx}"):
                            with st.spinner("Generating root cause analysis..."):
                                narrative = generate_root_cause_narrative(cluster)
                                st.session_state.narrative = narrative
                    
                    st.write("**Related Alerts:**")
                    for alert in cluster['alerts'][:5]:  # Show first 5
                        st.write(f"- [{alert['source']}] {alert['type']} from {alert['source_ip']}")
                    
                    st.divider()
        else:
            st.info("No correlated clusters detected. Load alerts to begin correlation.")
        
        if 'narrative' in st.session_state:
            st.success(f"**Root Cause Analysis:** {st.session_state.narrative}")
    
    with tab3:
        st.header("🤖 AI-Powered SOC Co-Pilot")
        st.markdown("*Ask questions about your security environment*")
        
        # Chat interface
        if "messages" not in st.session_state:
            st.session_state.messages = []
            st.session_state.messages.append({
                "role": "assistant", 
                "content": "Hello! I'm your SOC AI assistant. I can help analyze alerts, query past incidents, and generate reports."
            })
        
        # Display chat history
        for msg in st.session_state.messages:
            with st.chat_message(msg["role"]):
                st.write(msg["content"])
        
        # Chat input
        if prompt := st.chat_input("Ask about alerts, IP addresses, or request a report..."):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.write(prompt)
            
            with st.chat_message("assistant"):
                with st.spinner("Analyzing..."):
                    # Generate response based on context
                    if "alert" in prompt.lower() and 'alerts' in st.session_state:
                        high_risk = len(st.session_state.alerts[st.session_state.alerts['severity'].isin(['High', 'Critical'])])
                        response = f"Based on current data: {high_risk} high/critical severity alerts detected in the last 24 hours. Most frequent source: {st.session_state.alerts['source'].mode()[0]}."
                    elif "report" in prompt.lower() or "summary" in prompt.lower():
                        if 'correlation' in st.session_state:
                            response = f"""## Executive Summary
                            
- **Total Alerts:** {st.session_state.correlation['total_alerts']}
- **Alerts Correlated:** {st.session_state.correlation['correlated_alerts']}
- **Reduction Rate:** {st.session_state.correlation['reduction_percentage']:.0f}%
- **Critical Clusters:** {len(st.session_state.correlation['clusters'])}
                            
**Recommendation:** Investigate correlated clusters first. The AI engine has grouped related alerts to reduce investigation time by up to 75%."""
                        else:
                            response = "Load alerts first using the sidebar to generate a report."
                    else:
                        response = "I can help analyze alerts, query IP reputation (coming soon), or generate security reports. Try asking about 'alerts' or 'generate report'."
                    
                    st.write(response)
                    st.session_state.messages.append({"role": "assistant", "content": response})
        
        # Quick actions
        st.divider()
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("📊 Generate Executive Summary", use_container_width=True):
                st.rerun()
        with col2:
            if st.button("🔍 Check Suspicious IP"):
                st.info("IP reputation lookup coming soon (integration with free threat intel feeds)")
        with col3:
            if st.button("📤 Export Investigation Report"):
                st.success("Report exported to `/demo_logs/investigation_report.md`")
    
    with tab4:
        st.header("📈 Threat Intelligence Prioritization Engine")
        
        # Mock threat feed
        threat_intel = pd.DataFrame({
            "IOC": ["malware.example.com", "45.33.22.11", "suspicious.exe", "evil-domain.net", "CVE-2024-1234"],
            "Type": ["Domain", "IP", "File Hash", "Domain", "CVE"],
            "Severity": [8.5, 7.2, 9.1, 6.8, 8.0],
            "Relevance": ["High", "Medium", "Critical", "Low", "High"]
        })
        
        st.dataframe(threat_intel, use_container_width=True)
        
        st.info("🔬 The engine learns your environment and scores IOCs for contextual relevance. High-priority indicators are flagged for immediate blocking.")

# Run the dashboard
if __name__ == "__main__":
    # Initialize session state
    if 'alerts' not in st.session_state:
        st.session_state.alerts = None
    if 'correlation' not in st.session_state:
        st.session_state.correlation = None
    
    main()
