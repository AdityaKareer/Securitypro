# sudo python3 generate_report.py scan_results/43.205.151.144
import argparse
import os
import re
from datetime import datetime

os.system("pip install reportlab")
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

# Set up argument parser
parser = argparse.ArgumentParser(
    description="Generate a PDF report based on scan results."
)
parser.add_argument("output_dir", help="Directory containing scan results")
args = parser.parse_args()
output_dir = args.output_dir.strip()

# Define paths to scan results and report
nmap_file = os.path.join(output_dir, "nmap_output.xml")
nikto_file = os.path.join(output_dir, "nikto_output.xml")
report_path = os.path.join(output_dir, "vapt_report.pdf")

# Check if output_dir exists
if not os.path.isdir(output_dir):
    print(f"Error: The directory {output_dir} does not exist.")
    exit(1)

# Ensure the files exist
if not os.path.isfile(nmap_file):
    print(f"Error: Nmap output file {nmap_file} does not exist.")
    exit(1)
if not os.path.isfile(nikto_file):
    print(f"Error: Nikto output file {nikto_file} does not exist.")
    exit(1)


import xml.etree.ElementTree as ET


def parse_nmap_results(filepath):
    """Parse Nmap scan results."""
    open_ports = []
    filtered_ports = []
    host_status = ""
    mysql_version_detected = False
    target_hostname = None
    target_ip = None
    start_time = None
    end_time = None

    # Parse the XML file
    tree = ET.parse(filepath)
    root = tree.getroot()

    # Extract scan start and end times
    scan_info = root.find("runstats")
    if scan_info is not None:
        start_time_attr = root.attrib.get("start")
        if start_time_attr:
            start_time = datetime.fromtimestamp(int(start_time_attr)).strftime(
                "%B %d, %Y %H:%M:%S"
            )
        end_time_element = scan_info.find("finished")
        if end_time_element is not None:
            end_time_attr = end_time_element.attrib.get("time")
            if end_time_attr:
                end_time = datetime.fromtimestamp(int(end_time_attr)).strftime(
                    "%B %d, %Y %H:%M:%S"
                )

    # Extract target IP and hostname
    host = root.find("host")
    if host is not None:
        address = host.find("address")
        if address is not None:
            target_ip = address.attrib.get("addr")
            target_hostname = address.attrib.get(
                "addr", "Unknown"
            )  # Assuming hostname might not be available

        # Extract host status
        status = host.find("status")
        if status is not None:
            host_status = status.attrib.get("state", "Unknown")

    # Extract ports
    ports = root.findall(".//port")
    for port in ports:
        port_id = port.attrib.get("portid")
        service = port.find("service")
        state = port.find("state")

        if state is not None and state.attrib.get("state") == "open":
            service_name = (
                service.attrib.get("name", "Unknown")
                if service is not None
                else "Unknown"
            )
            open_ports.append([port_id, service_name])
            if "mysql" in service_name.lower():
                mysql_version_detected = True
        elif state is not None and state.attrib.get("state") == "filtered":
            service_name = (
                service.attrib.get("name", "Unknown")
                if service is not None
                else "Unknown"
            )
            filtered_ports.append([port_id, service_name])

    # Calculate total ports scanned
    total_ports_scanned = len(ports)

    return (
        open_ports,
        filtered_ports,
        host_status,
        mysql_version_detected,
        target_hostname,
        target_ip,
        start_time,
        end_time,
        total_ports_scanned,
    )


def parse_nikto_results(filepath):
    """Parse Nikto scan results."""
    findings = []
    with open(filepath, "r") as file:
        lines = file.readlines()
        for line in lines:
            if "No web server found" in line:
                findings.append("No web server detected on port 80.")
    return findings


def generate_report(nmap_results, nikto_results, report_filepath):
    """Generate a structured PDF report based on scan results."""
    (
        open_ports,
        filtered_ports,
        host_status,
        mysql_version_detected,
        target_hostname,
        target_ip,
        start_time,
        end_time,
        total_ports_scanned,
    ) = nmap_results
    nikto_findings = nikto_results
    # nikto_findings,nikto_start_time,nikto_end_time,total_tests_run = nikto_results

    doc = SimpleDocTemplate(report_filepath, pagesize=letter)
    styles = getSampleStyleSheet()

    # Custom Styles
    title_style = styles["Title"]
    heading_style = styles["Heading1"]
    normal_style = styles["Normal"]
    section_heading_style = ParagraphStyle(
        "SectionHeading", parent=styles["Heading2"], spaceAfter=12, fontSize=14
    )

    content = []

    # Title
    content.append(Paragraph("VAPT Report", title_style))
    content.append(Spacer(1, 12))

    # Introduction
    content.append(Paragraph("1. Introduction", heading_style))
    content.append(
        Paragraph(
            f"Date of Report: {datetime.now().strftime('%B %d, %Y')}", normal_style
        )
    )
    content.append(Paragraph(f"Target Hostname: {target_hostname}", normal_style))
    content.append(Paragraph(f"Target IP: {target_ip}", normal_style))
    content.append(
        Paragraph(
            f"Scan Performed By: Automated Detection and Security Assessment (ADSA)",
            normal_style,
        )
    )
    content.append(
        Paragraph(
            f"Purpose: Identify vulnerabilities and security issues in the target environment.",
            normal_style,
        )
    )
    content.append(Spacer(1, 12))

    # Scan Summary
    content.append(Paragraph("2. Scan Summary", heading_style))
    content.append(Paragraph("2.1 Nmap Scan Summary", section_heading_style))
    # start_time and end_time are already extracted from the XML
    content.append(Paragraph(f"Scan Start Time: {start_time}", normal_style))
    content.append(Paragraph(f"Scan End Time: {end_time}", normal_style))

    # total_ports_scanned is already calculated based on open_ports + filtered_ports
    content.append(
        Paragraph(f"Total Ports Scanned: {total_ports_scanned}", normal_style)
    )

    # Open Ports
    if open_ports:
        content.append(Paragraph("Open Ports:", normal_style))
        table_data = [["Port Id", "Service Name"]] + [
            [port, service] for port, service in open_ports
        ]
        table = Table(table_data, colWidths=[doc.width / 3.0] * 2)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), "#f0f0f0"),
                    ("TEXTCOLOR", (0, 0), (-1, 0), "#000000"),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("GRID", (0, 0), (-1, -1), 1, "#d0d0d0"),
                ]
            )
        )
        content.append(table)

    # Filtered Ports
    if filtered_ports:
        content.append(Paragraph("Filtered Ports:", normal_style))
        table_data = [["Port Id", "Service Name"]] + [
            [port, service] for port, service in filtered_ports
        ]
        table = Table(table_data, colWidths=[doc.width / 3.0] * 2)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), "#f0f0f0"),
                    ("TEXTCOLOR", (0, 0), (-1, 0), "#000000"),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("GRID", (0, 0), (-1, -1), 1, "#d0d0d0"),
                ]
            )
        )
        content.append(table)

    content.append(Paragraph(f"Host Status: {host_status}", normal_style))

    # Nikto Scan Summary
    content.append(Paragraph("2.2 Nikto Scan Summary", section_heading_style))
   
    content.append(Paragraph("Target Port: 80", normal_style))
    content.append(Paragraph("Server Detected: N/A", normal_style))

    # Nikto Findings
    if nikto_findings:
        content.append(Paragraph("Findings:", normal_style))
        table_data = [[finding] for finding in nikto_findings]
        table = Table(table_data, colWidths=[doc.width / 2.0])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), "#f0f0f0"),
                    ("TEXTCOLOR", (0, 0), (-1, 0), "#000000"),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 1, "#d0d0d0"),
                ]
            )
        )
        content.append(table)
    open_ports_assessments = {
        "135": (
            "MSRPC",
            "Ensure that proper access controls are in place for MSRPC services to prevent unauthorized access.",
        ),
        "139": (
            "NetBIOS-SSN",
            "NetBIOS services should be restricted, and unused ports should be closed to avoid exposure to vulnerabilities.",
        ),
        "445": (
            "Microsoft-DS",
            "Ensure that SMB services are secured with proper authentication and access controls.",
        ),
        "3306": (
            "MySQL",
            "Ensure that the MySQL service is properly secured, and consider applying the latest patches and configurations to mitigate known vulnerabilities.",
        ),
        "8080": (
            "HTTP",
            "Ensure the HTTP service is secure, apply patches, and consider using HTTPS.",
        ),
        "21": (
            "FTP",
            "Ensure that FTP is using secure configurations or replace with a secure alternative like SFTP.",
        ),
        "22": (
            "SSH",
            "Ensure SSH is secured with strong passwords or key-based authentication and disable root login if not needed.",
        ),
        "80": (
            "HTTP",
            "Ensure that the HTTP service is secure and consider using HTTPS for encrypted communication.",
        ),
        "443": (
            "HTTPS",
            "Ensure HTTPS configuration uses strong encryption standards and secure certificates.",
        ),
    }

    # Vulnerability Assessment
    content.append(Paragraph(" ", section_heading_style)) # for spacing before new section
    content.append(Paragraph("3. Vulnerability Assessment", heading_style))
    section_counter = 1  # Start numbering for subsections

    # If there are open ports, add related sections dynamically
    if open_ports:
        content.append(
            Paragraph(
                f"3.{section_counter} Open Ports and Services", section_heading_style
            )
        )
        section_counter += 1  # Increment section counter

        for port, service in open_ports:
            content.append(Paragraph(f"Port {port}/tcp ({service}):", normal_style))
            if port in open_ports_assessments:
                service_name, recommendation = open_ports_assessments[port]
                content.append(Paragraph(f"Service: {service_name}", normal_style))
                content.append(
                    Paragraph(f"Recommendation: {recommendation}", normal_style)
                )

    # Filtered Ports Section (if no open ports, this becomes 3.1)
    if filtered_ports:
        content.append(
            Paragraph(f"3.{section_counter} Filtered Ports", section_heading_style)
        )
        content.append(
            Paragraph(
                "Filtered ports may indicate that they are protected by a firewall or that the service is not responding to probes. Review security controls for these ports.",
                normal_style,
            )
        )
        section_counter += 1  # Increment section counter if used

    # Web Application Security (only added if findings exist)
    if nikto_findings:
        content.append(
            Paragraph(
                f"3.{section_counter} Web Application Security", section_heading_style
            )
        )
        for finding in nikto_findings:
            content.append(Paragraph(f"- {finding}", normal_style))

 
    # Conclusion
    content.append(Paragraph(" ", section_heading_style)) # for spacing before new section
    content.append(Paragraph("4. Conclusion", heading_style))
    content.append(
        Paragraph(
            "This assessment highlights the key areas where the target system can be improved. Addressing the identified issues will enhance the security posture and reduce potential risks. Regular security assessments and best practices should be followed to maintain a secure environment.",
            normal_style,
        )
    )

    # Appendices
    content.append(Paragraph(" ", section_heading_style)) # for spacing before new section
    content.append(Paragraph("5. Appendices", heading_style))
    content.append(Paragraph("5.1 Tools Used", section_heading_style))
    content.append(
        Paragraph(
            "- Nmap: Network scanner for identifying open ports and services.",
            normal_style,
        )
    )
    content.append(
        Paragraph(
            "- Nikto: Web server scanner for identifying common vulnerabilities and misconfigurations.",
            normal_style,
        )
    )

    content.append(Paragraph("5.2 References", section_heading_style))
    content.append(
        Paragraph("- [Nmap Documentation](https://nmap.org/docs.html)", normal_style)
    )
    content.append(
        Paragraph("- [Nikto Documentation](https://cirt.net/Nikto2)", normal_style)
    )

    # Build the PDF
    doc.build(content)


if __name__ == "__main__":
    nmap_results = parse_nmap_results(nmap_file)
    nikto_results = parse_nikto_results(nikto_file)
    generate_report(nmap_results, nikto_results, report_path)
