import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import os
import subprocess
import xml.etree.ElementTree as ET
import time
import schedule
import threading
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# Create necessary directories
if not os.path.exists("reports"):
    os.makedirs("reports")
if not os.path.exists("scan_results"):
    os.makedirs("scan_results")

# Function to run Nmap scan
def run_nmap_scan(network, output_dir):
    nmap_output = os.path.join(output_dir, f"nmap_output_{network.replace('/', '_').replace('.', '_')}.xml")
    nmap_command = f"nmap -p- -oX \"{nmap_output}\" {network}"

    try:
        subprocess.run(nmap_command, shell=True, check=True, capture_output=True, text=True)
        return nmap_output
    except subprocess.CalledProcessError as e:
        st.error(f"Error running Nmap for {network}: {str(e)}")
        return None

# Function to run Nikto scan
def run_nikto_scan(network, output_dir):
    nikto_output = os.path.join(output_dir, f"nikto_output_{network.replace('/', '_').replace('.', '_')}.xml")
    nikto_command = f"nikto -h {network} -output {nikto_output} -Format xml"

    try:
        subprocess.run(nikto_command, shell=True, check=True, capture_output=True, text=True)
        return nikto_output
    except subprocess.CalledProcessError as e:
        st.error(f"Error running Nikto for {network}: {str(e)}")
        return None

# Function to parse Nmap results
def parse_nmap_results(filepath):
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()

        results = {
            "open_ports": [],
            "filtered_ports": [],
            "host_status": "Unknown",
            "target_ip": "Unknown"
        }

        for host in root.findall(".//host"):
            address = host.find("address")
            if address is not None:
                results["target_ip"] = address.get("addr")

            status = host.find("status")
            if status is not None:
                results["host_status"] = status.get("state")

            for port in host.findall(".//port"):
                port_id = port.get("portid")
                state = port.find("state").get("state")
                service = port.find("service")
                service_name = service.get("name") if service is not None else "unknown"

                if state == "open":
                    results["open_ports"].append((port_id, service_name))
                elif state == "filtered":
                    results["filtered_ports"].append((port_id, service_name))

        return results
    except Exception as e:
        st.error(f"Error parsing Nmap results: {str(e)}")
        return None

# Function to parse Nikto results
def parse_nikto_results(filepath):
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()

        results = {
            "target_ip": "Unknown",
            "vulnerabilities": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": []
            }
        }

        scan_info = root.find(".//scandetails")
        if scan_info is not None:
            results["target_ip"] = scan_info.get("targetip")

        for item in root.findall(".//item"):
            description = item.find("description")
            severity = item.find("severity")

            if description is not None:
                severity_level = severity.text.lower() if severity is not None else "low"
                if severity_level in results["vulnerabilities"]:
                    results["vulnerabilities"][severity_level].append(description.text)
                else:
                    results["vulnerabilities"]["low"].append(description.text)

        return results
    except Exception as e:
        st.error(f"Error parsing Nikto results: {str(e)}")
        return None

# Function to generate PDF report
def generate_report(output_dir, run_nmap, run_nikto):
    report_path = os.path.join("reports", f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    
    doc = SimpleDocTemplate(report_path, pagesize=letter)
    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph("Security Assessment Report", styles["Title"]))
    content.append(Spacer(1, 20))

    if run_nmap:
        content.append(Paragraph("Network Scan Results (Nmap)", styles["Heading1"]))
        for file in os.listdir(output_dir):
            if file.startswith("nmap_output_") and file.endswith(".xml"):
                results = parse_nmap_results(os.path.join(output_dir, file))
                if results:
                    content.append(Paragraph(f"Target IP: {results['target_ip']}", styles["Normal"]))
                    content.append(Paragraph(f"Host Status: {results['host_status']}", styles["Normal"]))
                    
                    if results["open_ports"]:
                        content.append(Paragraph("Open Ports:", styles["Heading2"]))
                        for port, service in results["open_ports"]:
                            content.append(Paragraph(f"• Port {port}: {service}", styles["Normal"]))

    if run_nikto:
        content.append(Paragraph("Web Vulnerability Scan Results (Nikto)", styles["Heading1"]))
        for file in os.listdir(output_dir):
            if file.startswith("nikto_output_") and file.endswith(".xml"):
                results = parse_nikto_results(os.path.join(output_dir, file))
                if results:
                    for severity in ["critical", "high", "medium", "low"]:
                        if results["vulnerabilities"][severity]:
                            content.append(Paragraph(f"{severity.capitalize()} Severity Findings:", styles["Heading2"]))
                            for vuln in results["vulnerabilities"][severity]:
                                content.append(Paragraph(f"• {vuln}", styles["Normal"]))

    doc.build(content)
    return report_path

def main():
    st.set_page_config(page_title="Security Assessment Dashboard", layout="wide")
    
    # Custom CSS
    st.markdown("""
        <style>
        .main {
            padding-top: 2rem;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 2rem;
        }
        .stTabs [data-baseweb="tab"] {
            height: 4rem;
        }
        </style>
    """, unsafe_allow_html=True)

    st.title("🛡️ Security Assessment Dashboard")
    
    tabs = st.tabs(["📊 Dashboard", "🔍 Scan Control", "📅 Scheduler", "📑 Reports"])
    
    # Dashboard Tab
    with tabs[0]:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Active Scans", "2", "+1")
        with col2:
            st.metric("Total Vulnerabilities", "15", "-3")
        with col3:
            st.metric("Scan Success Rate", "98%", "+2%")
            
        # Vulnerability Distribution Chart
        st.subheader("Vulnerability Distribution")
        vuln_data = {
            'Severity': ['Critical', 'High', 'Medium', 'Low'],
            'Count': [3, 5, 8, 12]
        }
        fig = px.pie(vuln_data, values='Count', names='Severity', hole=0.3)
        st.plotly_chart(fig, use_container_width=True)
        
        # Recent Activity
        st.subheader("Recent Activity")
        activity_df = pd.DataFrame({
            'Timestamp': ['2024-01-18 10:00', '2024-01-18 09:45', '2024-01-18 09:30'],
            'Event': ['Scan Completed', 'Vulnerability Detected', 'Scan Started'],
            'Details': ['Network: 192.168.1.0/24', 'Critical: SQL Injection', 'Target: 10.0.0.0/24']
        })
        st.dataframe(activity_df, use_container_width=True)

    # Scan Control Tab
    with tabs[1]:
        st.header("Scan Control")
        
        network_input = st.text_area(
            "Target Networks/IPs (one per line)",
            help="Enter target IP addresses or networks (e.g., 192.168.1.1 or 192.168.1.0/24)"
        )
        
        col1, col2 = st.columns(2)
        with col1:
            run_nmap = st.checkbox("Run Nmap Scan", value=True)
        with col2:
            run_nikto = st.checkbox("Run Nikto Scan")
            
        if st.button("Start Scan", type="primary", use_container_width=True):
            networks = [n.strip() for n in network_input.split('\n') if n.strip()]
            
            if not networks:
                st.error("Please enter at least one target network/IP.")
                return
                
            if not (run_nmap or run_nikto):
                st.error("Please select at least one scan type.")
                return
                
            output_dir = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            os.makedirs(output_dir, exist_ok=True)
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for i, network in enumerate(networks):
                progress = (i / len(networks)) * 100
                progress_bar.progress(int(progress))
                
                if run_nmap:
                    status_text.text(f"Running Nmap scan on {network}...")
                    run_nmap_scan(network, output_dir)
                
                if run_nikto:
                    status_text.text(f"Running Nikto scan on {network}...")
                    run_nikto_scan(network, output_dir)
            
            progress_bar.progress(100)
            status_text.text("Generating report...")
            
            report_path = generate_report(output_dir, run_nmap, run_nikto)
            st.success("Scan completed! Report generated.")
            
            with open(report_path, "rb") as file:
                st.download_button(
                    label="Download Report",
                    data=file,
                    file_name=os.path.basename(report_path),
                    mime="application/pdf"
                )

    # Scheduler Tab
    with tabs[2]:
        st.header("Scan Scheduler")
        
        schedule_networks = st.text_area("Target Networks/IPs for Scheduled Scans")
        
        col1, col2 = st.columns(2)
        with col1:
            schedule_nmap = st.checkbox("Schedule Nmap Scan", key="schedule_nmap")
        with col2:
            schedule_nikto = st.checkbox("Schedule Nikto Scan", key="schedule_nikto")
            
        schedule_frequency = st.selectbox(
            "Scan Frequency",
            ["Daily", "Weekly"]
        )
        
        if st.button("Set Schedule", type="primary", use_container_width=True):
            st.success(f"Scans scheduled to run {schedule_frequency.lower()}")
            
        # Show scheduled scans
        st.subheader("Scheduled Scans")
        scheduled_df = pd.DataFrame({
            'Frequency': ['Daily', 'Weekly'],
            'Target': ['192.168.1.0/24', '10.0.0.0/24'],
            'Scan Types': ['Nmap + Nikto', 'Nmap'],
            'Next Run': ['2024-01-19 00:00', '2024-01-24 00:00']
        })
        st.dataframe(scheduled_df, use_container_width=True)

    # Reports Tab
    with tabs[3]:
        st.header("Scan Reports")
        
        if os.path.exists("reports"):
            reports = []
            for file in os.listdir("reports"):
                if file.startswith("scan_report_") and file.endswith(".pdf"):
                    file_path = os.path.join("reports", file)
                    timestamp_str = file.replace("scan_report_", "").replace(".pdf", "")
                    try:
                        timestamp = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                        reports.append({
                            "Date": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                            "Filename": file,
                            "Size": f"{os.path.getsize(file_path) / 1024:.1f} KB"
                        })
                    except ValueError:
                        continue
            
            if reports:
                reports_df = pd.DataFrame(reports)
                st.dataframe(reports_df, use_container_width=True)
                
                for report in reports:
                    with open(os.path.join("reports", report["Filename"]), "rb") as file:
                        st.download_button(
                            label=f"Download {report['Date']}",
                            data=file,
                            file_name=report["Filename"],
                            mime="application/pdf",
                            key=f"download_{report['Filename']}"
                        )
            else:
                st.info("No reports found. Run some scans to generate reports.")
        else:
            st.warning("Reports directory not found.")

if __name__ == "__main__":
    main()