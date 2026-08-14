"""Streamlit dashboard for the EnergyShield cybersecurity monitoring lab."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st


# This makes the dashboard command work from any current directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import DATA_DIRECTORY  # noqa: E402
from src.log_loader import LogLoadError, load_all_events  # noqa: E402
from src.reporting import build_incident_report, save_incident_report  # noqa: E402
from src.utils import analyze_security_events, build_summary  # noqa: E402


SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "WARNING": "#eab308",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
    "INFO": "#38bdf8",
}


st.set_page_config(
    page_title="EnergyShield SOC Lab",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
        .stApp { background-color: #07111f; color: #e5eef9; }
        [data-testid="stSidebar"] { background-color: #0b1728; }
        [data-testid="stMetric"] {
            background: linear-gradient(145deg, #0d1d31, #10243b);
            border: 1px solid #203b58;
            border-radius: 12px;
            padding: 14px 16px;
        }
        [data-testid="stMetricLabel"] { color: #91a9c4; }
        [data-testid="stMetricValue"] { color: #f8fafc; }
        .hero {
            padding: 1.4rem 1.6rem;
            border: 1px solid #244765;
            border-radius: 14px;
            background: linear-gradient(120deg, #0b2137, #0d2e35);
            margin-bottom: 1rem;
        }
        .hero-kicker {
            color: #55d6be;
            font-weight: 700;
            letter-spacing: .12rem;
            font-size: .78rem;
        }
        .hero h1 { margin: .25rem 0; color: #f8fafc; }
        .hero p { margin: 0; color: #b6c7da; }
        .simulation-note {
            border-left: 3px solid #55d6be;
            padding-left: .8rem;
            color: #a9bfd4;
        }
        div[data-testid="stDataFrame"] {
            border: 1px solid #203b58;
            border-radius: 10px;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data
def load_dashboard_data() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Load and analyze fixture data once per Streamlit session."""

    events, warnings = load_all_events(DATA_DIRECTORY)
    detections = analyze_security_events(events)
    return events, detections, warnings


def multiselect_filter(
    frame: pd.DataFrame, label: str, column: str
) -> list[str]:
    """Render a sidebar multi-select whose empty state means 'show all'."""

    options = sorted(value for value in frame[column].dropna().unique().tolist() if value)
    return st.sidebar.multiselect(label, options, help="Leave empty to include all values.")


def apply_filters(
    frame: pd.DataFrame, selected_filters: dict[str, list[str]]
) -> pd.DataFrame:
    """Apply only filters where the user selected one or more values."""

    filtered = frame.copy()
    for column, selected_values in selected_filters.items():
        if selected_values:
            filtered = filtered[filtered[column].isin(selected_values)]
    return filtered


def style_chart(figure: Any, height: int = 330) -> Any:
    """Apply a consistent dark SOC visual style to a Plotly figure."""

    figure.update_layout(
        height=height,
        margin=dict(l=12, r=12, t=45, b=12),
        paper_bgcolor="#0b1728",
        plot_bgcolor="#0b1728",
        font_color="#c8d7e8",
        title_font_color="#f1f5f9",
        legend_title_text="",
    )
    figure.update_xaxes(gridcolor="#1b3047")
    figure.update_yaxes(gridcolor="#1b3047")
    return figure


def render_metrics(
    events: list[dict[str, Any]], detections: list[dict[str, Any]]
) -> None:
    """Display five headline monitoring cards."""

    summary = build_summary(events, detections)
    columns = st.columns(5)
    labels_and_values = [
        ("TOTAL EVENTS", summary["total_events"]),
        ("ACTIVE ALERTS", summary["active_alerts"]),
        ("CRITICAL ALERTS", summary["critical_alerts"]),
        ("HIGH RISK SYSTEMS", summary["high_risk_systems"]),
        ("PRIVILEGED ALERTS", summary["privileged_alerts"]),
    ]
    for column, (label, value) in zip(columns, labels_and_values):
        column.metric(label, value)


def render_charts(events_frame: pd.DataFrame, alerts_frame: pd.DataFrame) -> None:
    """Render the requested portfolio visualizations."""

    left, middle, right = st.columns(3)

    severity_order = ["CRITICAL", "HIGH", "WARNING", "MEDIUM", "LOW", "INFO"]
    severity_counts = (
        alerts_frame["severity"]
        .value_counts()
        .reindex(severity_order, fill_value=0)
        .reset_index()
    )
    severity_counts.columns = ["Severity", "Alerts"]
    severity_chart = px.bar(
        severity_counts,
        x="Severity",
        y="Alerts",
        color="Severity",
        color_discrete_map=SEVERITY_COLORS,
        title="Alerts by Severity",
    )
    left.plotly_chart(style_chart(severity_chart), use_container_width=True)

    event_times = events_frame.copy()
    event_times["timestamp"] = pd.to_datetime(event_times["timestamp"], errors="coerce")
    timeline = (
        event_times.dropna(subset=["timestamp"])
        .set_index("timestamp")
        .resample("2h")
        .size()
        .reset_index(name="Events")
    )
    timeline_chart = px.area(
        timeline,
        x="timestamp",
        y="Events",
        title="Events over Time",
        color_discrete_sequence=["#38bdf8"],
    )
    middle.plotly_chart(style_chart(timeline_chart), use_container_width=True)

    top_sources = alerts_frame["source_ip"].value_counts().head(7).reset_index()
    top_sources.columns = ["Source IP", "Alerts"]
    source_chart = px.bar(
        top_sources,
        x="Alerts",
        y="Source IP",
        orientation="h",
        title="Top Alert Sources",
        color_discrete_sequence=["#55d6be"],
    )
    source_chart.update_layout(yaxis={"categoryorder": "total ascending"})
    right.plotly_chart(style_chart(source_chart), use_container_width=True)

    left, middle, right = st.columns(3)
    top_targets = alerts_frame["affected_host"].value_counts().head(7).reset_index()
    top_targets.columns = ["System", "Alerts"]
    target_chart = px.bar(
        top_targets,
        x="Alerts",
        y="System",
        orientation="h",
        title="Top Targeted Systems",
        color_discrete_sequence=["#a78bfa"],
    )
    target_chart.update_layout(yaxis={"categoryorder": "total ascending"})
    left.plotly_chart(style_chart(target_chart), use_container_width=True)

    login_events = events_frame[events_frame["failed_logins"] > 0].nlargest(
        8, "failed_logins"
    )
    login_chart = px.bar(
        login_events,
        x="hostname",
        y="failed_logins",
        color="privileged_account",
        title="Failed Login Attempts",
        labels={"hostname": "System", "failed_logins": "Failures"},
        color_discrete_map={True: "#ef4444", False: "#eab308"},
    )
    middle.plotly_chart(style_chart(login_chart), use_container_width=True)

    threat_counts = alerts_frame["event_type"].value_counts().reset_index()
    threat_counts.columns = ["Event Type", "Alerts"]
    threat_chart = px.bar(
        threat_counts,
        x="Alerts",
        y="Event Type",
        orientation="h",
        title="Threats by Event Type",
        color_discrete_sequence=["#f97316"],
    )
    threat_chart.update_layout(yaxis={"categoryorder": "total ascending"})
    right.plotly_chart(style_chart(threat_chart), use_container_width=True)

    system_risk = (
        alerts_frame.groupby("affected_host", as_index=False)["risk_score"]
        .max()
        .sort_values("risk_score", ascending=False)
    )
    risk_chart = px.bar(
        system_risk,
        x="affected_host",
        y="risk_score",
        color="risk_score",
        title="Maximum Risk Score by System",
        labels={"affected_host": "System", "risk_score": "Risk Score"},
        color_continuous_scale=["#22c55e", "#eab308", "#ef4444"],
        range_color=[0, 100],
    )
    risk_chart.add_hline(y=80, line_dash="dot", line_color="#ef4444")
    st.plotly_chart(style_chart(risk_chart, height=360), use_container_width=True)


def render_alert_details(selected_alert: dict[str, Any]) -> None:
    """Show full context and report actions for one selected alert."""

    severity = selected_alert["severity"]
    st.subheader(f"{severity}: {selected_alert['rule_name']}")
    detail_columns = st.columns(4)
    detail_columns[0].metric("Risk Score", f"{selected_alert['risk_score']}/100")
    detail_columns[1].metric("Affected User", selected_alert["affected_user"])
    detail_columns[2].metric("Source IP", selected_alert["source_ip"])
    detail_columns[3].metric("System", selected_alert["affected_host"])

    overview_tab, risk_tab, mitre_tab, response_tab = st.tabs(
        ["Alert Details", "Risk Explanation", "MITRE ATT&CK", "Response Playbook"]
    )
    with overview_tab:
        st.write(selected_alert["description"])
        st.markdown("**Why it triggered**")
        st.write(selected_alert["why_triggered"])
        st.caption(
            f"Alert {selected_alert['alert_id']} · Rule {selected_alert['rule_id']} · "
            f"{selected_alert['timestamp']}"
        )
        with st.expander("Related fictional event evidence"):
            st.json(selected_alert["event_data"])

    with risk_tab:
        st.write(
            f"**{selected_alert['risk_level']} — "
            f"{selected_alert['risk_score']} out of 100**"
        )
        for factor in selected_alert["risk_factors"]:
            st.write(f"- {factor}")

    with mitre_tab:
        st.write(f"**Tactic:** {selected_alert['mitre_tactic']}")
        st.write(f"**Technique:** {selected_alert['mitre_technique']}")
        st.write(f"**Technique ID:** {selected_alert['mitre_technique_id']}")
        st.caption(
            "ATT&CK mappings support analyst education. 'Needs verification' is used "
            "when a generic event does not justify a confident technique mapping."
        )

    response = selected_alert["response_playbook"]
    with response_tab:
        st.markdown("**Recommended investigation**")
        for number, step in enumerate(response["investigation"], start=1):
            st.write(f"{number}. {step}")
        st.markdown("**Potential containment (with authorization)**")
        for number, step in enumerate(response["containment"], start=1):
            st.write(f"{number}. {step}")
        st.warning(response["safety_note"])

    report_text = build_incident_report(selected_alert)
    action_left, action_right = st.columns(2)
    with action_left:
        if st.button("Save report to reports/", use_container_width=True):
            report_path = save_incident_report(selected_alert)
            st.success(f"Saved {report_path.name}")
    with action_right:
        st.download_button(
            "Download Markdown report",
            report_text,
            file_name=f"{selected_alert['alert_id']}_incident_report.md",
            mime="text/markdown",
            use_container_width=True,
        )


def main() -> None:
    """Render the full local SOC dashboard."""

    st.markdown(
        """
        <div class="hero">
            <div class="hero-kicker">DEFENSIVE CYBERSECURITY PORTFOLIO LAB</div>
            <h1>⚡ EnergyShield</h1>
            <p>Energy Infrastructure Cybersecurity Monitoring Lab</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    try:
        events, detections, warnings = load_dashboard_data()
    except LogLoadError as error:
        st.error(f"Could not load the sample events: {error}")
        st.stop()

    for warning in warnings:
        st.warning(warning)

    events_frame = pd.DataFrame(events)
    alerts_frame = pd.DataFrame(detections)
    events_frame["failed_logins"] = pd.to_numeric(
        events_frame["failed_logins"], errors="coerce"
    ).fillna(0)

    st.sidebar.title("Alert Filters")
    st.sidebar.caption("No selection means all values.")
    selected_filters = {
        "severity": multiselect_filter(alerts_frame, "Severity", "severity"),
        "affected_host": multiselect_filter(alerts_frame, "System", "affected_host"),
        "affected_user": multiselect_filter(alerts_frame, "Username", "affected_user"),
        "source_ip": multiselect_filter(alerts_frame, "Source IP", "source_ip"),
        "event_type": multiselect_filter(alerts_frame, "Event Type", "event_type"),
    }
    filtered_alerts = apply_filters(alerts_frame, selected_filters)
    filtered_detections = filtered_alerts.to_dict("records")

    render_metrics(events, detections)
    st.caption(
        f"Showing {len(filtered_alerts)} of {len(alerts_frame)} alerts after filtering."
    )

    if filtered_alerts.empty:
        st.info("No alerts match the selected filters.")
        st.stop()

    render_charts(events_frame, filtered_alerts)

    st.subheader("Recent Security Alerts")
    table = filtered_alerts[
        [
            "timestamp",
            "severity",
            "rule_name",
            "affected_user",
            "source_ip",
            "affected_host",
            "risk_score",
            "mitre_technique",
        ]
    ].rename(
        columns={
            "timestamp": "Timestamp",
            "severity": "Severity",
            "rule_name": "Detection",
            "affected_user": "Username",
            "source_ip": "Source IP",
            "affected_host": "System",
            "risk_score": "Risk Score",
            "mitre_technique": "MITRE Technique",
        }
    )
    st.dataframe(table, use_container_width=True, hide_index=True, height=420)

    st.subheader("Investigate an Alert")
    selected_alert_id = st.selectbox(
        "Select an alert",
        [alert["alert_id"] for alert in filtered_detections],
        format_func=lambda alert_id: next(
            f"{alert_id} · {alert['severity']} · {alert['rule_name']} · "
            f"{alert['affected_host']}"
            for alert in filtered_detections
            if alert["alert_id"] == alert_id
        ),
    )
    selected_alert = next(
        alert for alert in filtered_detections if alert["alert_id"] == selected_alert_id
    )
    render_alert_details(selected_alert)

    st.divider()
    st.markdown(
        """
        <p class="simulation-note">
        EnergyShield simulates cybersecurity monitoring around fictional operational
        technology systems. It does not implement or interact with real industrial
        control systems.
        </p>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()

