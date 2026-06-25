import os
from typing import Dict, List
import altair as alt
import pandas as pd
import requests
import streamlit as st

API_URL = os.getenv("BACKEND_API_URL", "http://localhost:8000")

st.set_page_config(page_title="CloudSOC Copilot", page_icon="shield", layout="wide")


def api_get(path: str):
    response = requests.get(f"{API_URL}{path}", timeout=15)
    response.raise_for_status()
    return response.json()


def api_post(path: str, **kwargs):
    response = requests.post(f"{API_URL}{path}", timeout=45, **kwargs)
    response.raise_for_status()
    return response.json()


def show_connection_status():
    try:
        health = api_get("/")
        st.sidebar.success(f"Backend: {health['status']} | {health['version']}")
    except Exception:
        st.sidebar.error("Backend is not reachable. Start FastAPI on port 8000.")


def severity_badge(severity: str) -> str:
    return severity or "Unknown"


def role_pages(role: str) -> List[str]:
    if role == "Executive":
        return ["Executive Summary", "Reports"]
    if role == "SOC Manager":
        return ["Security Overview", "Alerts Queue", "MITRE ATT&CK View", "Attack Timeline", "Vulnerability Prioritization", "Reports"]
    return [
        "Security Overview",
        "Upload Logs",
        "Alerts Queue",
        "Incident Detail",
        "MITRE ATT&CK View",
        "Attack Timeline",
        "Vulnerability Prioritization",
        "Detection Rules",
        "Reports",
    ]


def overview_page():
    st.title("CloudSOC Copilot Advanced")
    st.caption("AI-assisted SOC investigation platform with MITRE mapping, Sigma-style rules, Suricata support, and vulnerability prioritization")

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        if st.button("Load Advanced Demo Logs", use_container_width=True):
            result = api_post("/api/demo/load-samples")
            st.success(f"Loaded {result['events_ingested']} events from: {', '.join(result.get('files', []))}")
    with col_b:
        if st.button("Run Detection", use_container_width=True):
            result = api_post("/api/detect/run")
            st.success(f"Detection completed. Alerts created: {result['results']['total_alerts']}")
            st.json(result["results"])
    with col_c:
        if st.button("Reset Demo Database", use_container_width=True):
            result = api_post("/api/demo/reset")
            st.warning(result["message"])

    metrics = api_get("/api/metrics")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Events", metrics["events"])
    m2.metric("Total Alerts", metrics["alerts"])
    m3.metric("Critical Alerts", metrics["critical_alerts"])
    m4.metric("High Alerts", metrics["high_alerts"])

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Severity Breakdown")
        sev_df = pd.DataFrame([{"Severity": key, "Count": value} for key, value in metrics["severity_counts"].items()])
        st.bar_chart(sev_df.set_index("Severity"))
    with col2:
        st.subheader("Detected MITRE Tactics")
        tactic_df = pd.DataFrame(metrics.get("mitre_tactics", []), columns=["Tactic", "Alerts"])
        if not tactic_df.empty:
            st.bar_chart(tactic_df.set_index("Tactic"))
        else:
            st.info("No MITRE coverage yet. Run detection first.")

    col3, col4 = st.columns(2)
    with col3:
        st.subheader("Top Source IPs")
        top_ips = pd.DataFrame(metrics["top_source_ips"], columns=["Source IP", "Alerts"])
        st.dataframe(top_ips, use_container_width=True, hide_index=True)
    with col4:
        st.subheader("Log Sources")
        sources = pd.DataFrame(metrics.get("sources", []), columns=["Source", "Events"])
        st.dataframe(sources, use_container_width=True, hide_index=True)

    st.subheader("Recent Alerts")
    alerts = api_get("/api/alerts")
    if alerts:
        st.dataframe(pd.DataFrame(alerts), use_container_width=True, hide_index=True)
    else:
        st.info("No alerts yet. Load demo logs and run detection.")


def executive_summary_page():
    st.title("Executive Summary")
    metrics = api_get("/api/metrics")
    alerts = api_get("/api/alerts")

    m1, m2, m3 = st.columns(3)
    m1.metric("Total Alerts", metrics["alerts"])
    m2.metric("Critical", metrics["critical_alerts"])
    m3.metric("High", metrics["high_alerts"])

    if not alerts:
        st.info("No alerts available yet.")
        return

    critical = [a for a in alerts if a["severity"] == "Critical"]
    high = [a for a in alerts if a["severity"] == "High"]
    st.subheader("Business Risk Summary")
    st.write(
        f"CloudSOC Copilot identified {len(critical)} critical and {len(high)} high severity incidents. "
        "Priority focus should be credential compromise, exposed vulnerable services, and IDS-confirmed suspicious traffic."
    )
    st.subheader("Top Priority Incidents")
    top = pd.DataFrame(alerts[:5])[["severity", "risk_score", "title", "source_ip", "host", "mitre_tactic"]]
    st.dataframe(top, use_container_width=True, hide_index=True)


def upload_page():
    st.title("Upload Logs")
    st.write("Upload AWS CloudTrail JSON, Linux SSH auth logs, Suricata eve.json, Nmap XML, or Apache/Nginx access logs.")

    uploaded = st.file_uploader("Choose a log file", type=["json", "jsonl", "ndjson", "log", "txt", "xml"])
    if uploaded and st.button("Upload Log"):
        files = {"file": (uploaded.name, uploaded.getvalue())}
        result = api_post("/api/upload", files=files)
        st.success(f"Uploaded {result['filename']} with {result['events_ingested']} normalized events.")

    st.subheader("Current Events")
    events = api_get("/api/events")
    if events:
        st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)
    else:
        st.info("No events ingested yet.")


def alerts_page():
    st.title("Alerts Queue")
    alerts = api_get("/api/alerts")
    if not alerts:
        st.info("No alerts yet. Go to Overview, load demo logs, and run detection.")
        return

    df = pd.DataFrame(alerts)
    col1, col2 = st.columns(2)
    with col1:
        severity_filter = st.multiselect(
            "Filter by severity",
            options=sorted(df["severity"].dropna().unique()),
            default=list(sorted(df["severity"].dropna().unique())),
        )
    with col2:
        tactic_filter = st.multiselect(
            "Filter by MITRE tactic",
            options=sorted(df["mitre_tactic"].dropna().unique()),
            default=list(sorted(df["mitre_tactic"].dropna().unique())),
        )
    if severity_filter:
        df = df[df["severity"].isin(severity_filter)]
    if tactic_filter:
        df = df[df["mitre_tactic"].isin(tactic_filter)]

    columns = ["id", "created_at", "severity", "risk_score", "title", "user", "source_ip", "host", "status", "mitre_tactic", "mitre_technique"]
    st.dataframe(df[columns], use_container_width=True, hide_index=True)


def incident_detail_page():
    st.title("Incident Detail")
    alerts = api_get("/api/alerts")
    if not alerts:
        st.info("No alerts available.")
        return

    labels = [f"#{a['id']} | {a['severity']} | {a['title']} | {a.get('user') or a.get('host') or 'unknown'}" for a in alerts]
    selected_label = st.selectbox("Select alert", labels)
    selected_id = int(selected_label.split("|")[0].replace("#", "").strip())

    detail = api_get(f"/api/alerts/{selected_id}")
    alert = detail["alert"]
    evidence = detail["evidence"]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Severity", severity_badge(alert["severity"]))
    c2.metric("Risk Score", f"{alert['risk_score']}/100")
    c3.metric("User", alert.get("user") or "Unknown")
    c4.metric("Source IP", alert.get("source_ip") or "Unknown")

    st.subheader(alert["title"])
    st.write(alert["description"])

    st.subheader("MITRE ATT&CK Mapping")
    st.write(f"Tactic: **{alert.get('mitre_tactic') or 'Not mapped'}**")
    st.write(f"Technique: **{alert.get('mitre_technique') or 'Not mapped'}**")

    st.subheader("AI Investigation Summary")
    st.text_area("Summary", value=alert.get("ai_summary") or "No summary generated.", height=360)

    st.subheader("Evidence Timeline")
    rows = []
    for item in evidence:
        event = item["event"]
        rows.append({
            "Evidence Type": item["evidence_type"],
            "Time": event.get("timestamp"),
            "Source": event.get("source"),
            "Event Type": event.get("event_type"),
            "User": event.get("user"),
            "Source IP": event.get("source_ip"),
            "Host": event.get("host"),
            "Action": event.get("action"),
            "Status": event.get("status"),
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    with st.expander("Raw logs"):
        for item in evidence:
            event = item["event"]
            st.code(event.get("raw_event") or "", language="json" if event.get("source") in {"aws_cloudtrail", "suricata_eve", "nmap_scan"} else "text")

    if st.button("Export Markdown Report", use_container_width=True):
        result = api_post(f"/api/alerts/{selected_id}/report")
        st.success("Report generated.")
        st.code(result["report_path"])
        st.markdown(f"Download from backend: `{API_URL}{result['download_url']}`")


def mitre_page():
    st.title("MITRE ATT&CK View")
    data = api_get("/api/mitre/coverage")
    coverage = data.get("coverage", {})
    if not coverage:
        st.info("No MITRE coverage yet. Run detection first.")
    else:
        rows = []
        for tactic, techniques in coverage.items():
            for technique, count in techniques.items():
                rows.append({"Tactic": tactic, "Technique": technique, "Alert Count": count})
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.bar_chart(df.groupby("Tactic")["Alert Count"].sum())

    st.subheader("Available Detection Mappings")
    mappings = []
    for name, item in data.get("available_mappings", {}).items():
        mappings.append({"Rule Family": name, "Tactic": item.get("tactic"), "Technique": item.get("technique")})
    st.dataframe(pd.DataFrame(mappings), use_container_width=True, hide_index=True)


def timeline_page():
    st.title("Attack Timeline")
    events = api_get("/api/timeline")
    if not events:
        st.info("No events available.")
        return
    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    if df.empty:
        st.info("No timestamped events available.")
        return

    chart = (
        alt.Chart(df)
        .mark_circle(size=120)
        .encode(
            x=alt.X("timestamp:T", title="Time"),
            y=alt.Y("source:N", title="Log Source"),
            tooltip=["timestamp:T", "source:N", "event_type:N", "source_ip:N", "host:N", "action:N", "status:N"],
            color="event_type:N",
        )
        .interactive()
    )
    st.altair_chart(chart, use_container_width=True)
    st.dataframe(df[["timestamp", "source", "event_type", "user", "source_ip", "host", "action", "status"]], use_container_width=True, hide_index=True)


def vulnerability_page():
    st.title("Vulnerability Prioritization")
    st.write("This page uses Nmap scan results plus the local CISA KEV sample catalog to prioritize exposed services.")
    priorities = api_get("/api/vulnerabilities/priorities")
    if priorities:
        st.dataframe(pd.DataFrame(priorities), use_container_width=True, hide_index=True)
    else:
        st.info("No vulnerability priorities yet. Load demo logs or upload an Nmap XML scan, then run detection.")

    with st.expander("Local CISA KEV sample catalog"):
        kev = api_get("/api/threat-intel/cisa-kev")
        st.dataframe(pd.DataFrame(kev), use_container_width=True, hide_index=True)


def detection_rules_page():
    st.title("Sigma-style Detection Rules")
    rules = api_get("/api/detections/rules")
    if not rules:
        st.info("No Sigma-style YAML rules found.")
        return
    table = []
    for rule in rules:
        table.append({
            "Title": rule.get("title"),
            "ID": rule.get("id"),
            "Level": rule.get("level"),
            "Status": rule.get("status"),
            "Path": rule.get("path"),
            "Tags": ", ".join(rule.get("tags") or []),
        })
    st.dataframe(pd.DataFrame(table), use_container_width=True, hide_index=True)
    selected = st.selectbox("View rule details", [item["Path"] for item in table])
    rule = next((item for item in rules if item.get("path") == selected), None)
    if rule:
        st.json(rule)


def reports_page():
    st.title("Reports")
    st.write("Reports are generated from the Incident Detail page and saved in the `reports` folder.")
    st.info("Advanced version exports Markdown incident reports. PDF export can be added in the very advanced version.")


def main():
    show_connection_status()
    role = st.sidebar.selectbox("Dashboard role", ["SOC Analyst", "SOC Manager", "Executive"])
    st.sidebar.caption(f"Current role: {role}")
    pages = role_pages(role)
    page = st.sidebar.radio("Navigation", pages)

    try:
        if page == "Security Overview":
            overview_page()
        elif page == "Executive Summary":
            executive_summary_page()
        elif page == "Upload Logs":
            upload_page()
        elif page == "Alerts Queue":
            alerts_page()
        elif page == "Incident Detail":
            incident_detail_page()
        elif page == "MITRE ATT&CK View":
            mitre_page()
        elif page == "Attack Timeline":
            timeline_page()
        elif page == "Vulnerability Prioritization":
            vulnerability_page()
        elif page == "Detection Rules":
            detection_rules_page()
        elif page == "Reports":
            reports_page()
    except requests.HTTPError as exc:
        st.error(f"API error: {exc.response.text}")
    except requests.RequestException as exc:
        st.error(f"Could not connect to backend: {exc}")


if __name__ == "__main__":
    main()
