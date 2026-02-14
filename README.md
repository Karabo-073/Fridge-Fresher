<!-- Main SOC Analyst Portfolio README -->

<div align="center" style="font-family: Arial, sans-serif; line-height: 1.6;">

<u><h1>Global SOC Analyst Portfolio – Comprehensive Cybersecurity Labs</h1></u>

<br>


This portfolio presents a global-standard collection of hands-on Security Operations Center (SOC) labs and exercises, showcasing practical expertise in threat detection, vulnerability management, network defense, incident response, and malware triage. 
It demonstrates proficiency across multiple platforms, tools, and methodologies, emphasizing the ability to operate in enterprise-level environments and international cybersecurity frameworks. 
The portfolio highlights skills essential for protecting organizations against evolving cyber threats while adhering to global best practices in security monitoring, risk assessment, and response.

<br><br>

<u><h2>Portfolio Structure (Tree Diagram)</h2></u>

<pre>
Global_SOC_Analyst_Portfolio/
│
├── Vulnerability_Management
│     ├── Nmap Full TCP Scan
│     ├── Ping Sweep & Host Discovery
│     └── Web Vulnerability Assessment (Nikto / DVWA)
│
├── Linux_Log_Analysis
│     ├── Authentication & Failed Login Analysis
│     ├── Event Correlation & System Monitoring
│     └── Security Alert Validation
│
├── Firewall_Configuration & Network_Hardening
│     ├── Firewall Rule Implementation (pfSense)
│     ├── VLAN Segmentation & Access Policies
│     └── Network Traffic Monitoring & Logging
│
└── Incident_Response & Malware_Triage
      ├── Malware Detection & Analysis
      ├── Containment & Eradication Procedures
      └── Recovery, Documentation & Lessons Learned
</pre>

<br>

<u><h2>Global Tools & Platforms</h2></u>

<table border="1" cellpadding="8" cellspacing="0" align="center">
<tr>
<th>Category</th>
<th>Tools / Platforms</th>
<th>Purpose</th>
</tr>
<tr>
<td>Operating Systems</td>
<td>Kali Linux, Ubuntu, Windows Server, Metasploitable</td>
<td>Penetration testing, lab environments, cross-platform monitoring</td>
</tr>
<tr>
<td>Network & Vulnerability Tools</td>
<td>Nmap, Netcat, Nikto, OpenVAS</td>
<td>Network scanning, port/service enumeration, vulnerability assessment</td>
</tr>
<tr>
<td>Packet Analysis</td>
<td>Wireshark, tcpdump</td>
<td>Traffic inspection, anomaly detection, alert verification</td>
</tr>
<tr>
<td>Firewall & Hardening</td>
<td>pfSense</td>
<td>Perimeter defense, segmentation, access control</td>
</tr>
<tr>
<td>Log Analysis & SIEM</td>
<td>Linux Logs, Windows Sysmon, Splunk, ELK Stack</td>
<td>Event correlation, threat intelligence integration, monitoring</td>
</tr>
<tr>
<td>Malware & Forensics</td>
<td>Volatility, Sandbox Tools, Antivirus</td>
<td>Memory forensics, malware triage, root cause identification</td>
</tr>
<tr>
<td>Web Security Labs</td>
<td>DVWA, Metasploitable</td>
<td>Web application vulnerability exploitation, lab-based risk assessment</td>
</tr>
</table>

<br>

<u><h2>Practical Labs – Highlights</h2></u>

<div align="center"><u>Vulnerability Management & Scanning</u></div>
<pre>
Objective:
• Identify exposed services and vulnerabilities on internal lab network.
Commands:
• sudo nmap -sS -sV -O -p-
• nmap -sn
• nikto -h http://<target>
Findings:
• Live hosts discovered
• TCP ports and service versions enumerated
• Outdated web server software and misconfigurations identified
Analysis:
• Prioritize remediation based on exposed services
• Reduce attack surface and document findings
</pre>

<div align="center"><u>Linux Log Analysis & Monitoring</u></div>
<pre>
Objective:
• Detect failed logins and potential brute force attacks via system logs.
Commands:
• cat /var/log/auth.log | grep "Failed"
• journalctl -xe | grep -i "error"
Findings:
• Multiple failed login attempts and suspicious IPs
Analysis:
• Continuous monitoring essential for SOC alerting
• Correlate logs with threat intelligence feeds
</pre>

<div align="center"><u>Firewall Configuration & Network Hardening</u></div>
<pre>
Objective:
• Strengthen network perimeter and enforce access controls.
Commands:
• pfSense GUI / CLI for firewall and VLAN setup
Findings:
• Unauthorized traffic blocked
• Segmentation reduces lateral movement
Analysis:
• Demonstrates professional SOC-level network defense
</pre>

<div align="center"><u>Security Incident Response & Malware Triage</u></div>
<pre>
Objective:
• Simulate real-world malware incident, perform containment, eradication, and recovery.
Commands:
• Analyze logs (Linux/Windows/SIEM)
• Sandbox malware analysis and Volatility memory inspection
Findings:
• Malware detected, contained, and remediated
• Recovery completed and lessons documented
Analysis:
• Structured incident response ensures operational continuity
• Enhances SOC readiness and process documentation
</pre>

<br>

<u><h2>Professional Summary</h2></u>

This portfolio represents **global cybersecurity readiness** for enterprise SOC roles, demonstrating:

• Vulnerability management and exposure analysis  
• Linux/Windows log monitoring and alerting  
• Network scanning, firewall hardening, and segmentation  
• Malware triage, incident response, and recovery  
• Documentation and reporting following international SOC standards  

<br><br>

<div align="center"><u>Portfolio Ready for International Recruiters, GitHub, and SOC Analyst Opportunities</u></div>

</div>


