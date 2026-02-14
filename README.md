<!-- Centered Header -->
<div align="center">

# SOC Analyst Training Portfolio – 40 Projects

A comprehensive SOC analyst portfolio demonstrating expertise in network security, threat hunting, incident response, SOC automation, and enterprise security operations.

</div>

<hr>

<!-- Left-aligned Portfolio Tree -->
<pre>
SOC_Analyst_Portfolio/
├── Beginner_Projects_1-5/
│   ├── Nmap_Host_Discovery
│   │   ├── Objective: Scan network hosts and identify open ports
│   │   ├── Commands: nmap -sV -p- 10.10.10.10
│   │   └── Expected Results: List of open ports and services
│   ├── Linux_Log_Monitoring
│   │   ├── Objective: Monitor authentication logs
│   │   ├── Commands: tail -f /var/log/auth.log
│   │   └── Expected Results: Capture login attempts and failures
│   ├── Wireshark_Packet_Capture
│   │   ├── Objective: Capture network traffic for analysis
│   │   ├── Commands: wireshark or tcpdump -i eth0 -w capture.pcap
│   │   └── Expected Results: Packet capture for inspection
│   └── DVWA_Web_Scanning
│       ├── Objective: Scan web app vulnerabilities
│       ├── Commands: nikto -h http://10.10.10.10
│       └── Expected Results: List of web vulnerabilities
├── Intermediate_Projects_6-15/
│   ├── Service_Enumeration
│   │   ├── Objective: Identify running services and versions
│   │   ├── Commands: nmap -sV 10.10.10.10
│   │   └── Expected Results: Open ports with service details
│   ├── SIEM_Log_Correlation
│   │   ├── Objective: Correlate logs to detect anomalies
│   │   ├── Commands: Splunk queries / ELK searches
│   │   └── Expected Results: Detect suspicious patterns
│   ├── Network_and_HTTP_Enumeration
│   │   ├── Objective: Map network hosts and web endpoints
│   │   ├── Commands: nmap, curl, dirb
│   │   └── Expected Results: List of hosts and endpoints
│   └── Failed_Login_Analysis
│       ├── Objective: Detect brute-force attempts
│       ├── Commands: grep "Failed password" /var/log/auth.log
│       └── Expected Results: List of failed login attempts
├── Advanced_Projects_16-29/
│   ├── MITRE_ATT&CK_Threat_Mapping
│   │   ├── Objective: Map detected threats to MITRE ATT&CK
│   │   ├── Commands: Manual analysis, SIEM correlation
│   │   └── Expected Results: Threat tactics identified
│   ├── Cross_Platform_Endpoint_Monitoring
│   │   ├── Objective: Monitor Windows & Linux endpoints
│   │   ├── Commands: Sysmon, auditd, Wazuh agents
│   │   └── Expected Results: Alerts on abnormal activity
│   ├── Cloud_Security_Monitoring
│   │   ├── Objective: Monitor cloud services for anomalies
│   │   ├── Commands: Cloud SIEM dashboards / logs
│   │   └── Expected Results: Suspicious cloud activities detected
│   ├── UEBA_and_AI_Detection
│   │   ├── Objective: Detect anomalous user behavior
│   │   ├── Commands: UEBA analytics dashboards
│   │   └── Expected Results: Suspicious behavioral alerts
│   └── Red_Blue_Exercises
│       ├── Objective: Participate in attack-defense simulations
│       ├── Commands: Offensive & defensive tools
│       └── Expected Results: Detection and mitigation of attacks
└── Expert_Projects_30-40/
    ├── SOC_Architecture_Design
    │   ├── Objective: Design enterprise SOC structure
    │   ├── Commands: Network diagrams and policy setup
    │   └── Expected Results: Optimized SOC workflow
    ├── SOAR_Automation_and_AI_Integration
    │   ├── Objective: Automate incident response
    │   ├── Commands: Cortex XSOAR playbooks
    │   └── Expected Results: Faster response times
    ├── Threat_Intelligence_Program
    │   ├── Objective: Develop threat intelligence program
    │   ├── Commands: MISP, OTX feed integration
    │   └── Expected Results: Proactive threat detection
    ├── Zero_Trust_Deployment
    │   ├── Objective: Implement Zero Trust policies
    │   ├── Commands: MFA, micro-segmentation setup
    │   └── Expected Results: Reduced attack surface
    └── Executive_Dashboards_KPIs
        ├── Objective: Track SOC KPIs and metrics
        ├── Commands: Splunk, ELK dashboards
        └── Expected Results: MTTR, MTTD, threat trends monitored
</pre>

<hr>

<!-- Centered Skills Header -->
<div align="center">

## Skills Demonstrated

</div>

<!-- Left-aligned Skills Tree -->
<pre>
SOC_Skills/
├── Network_Security_and_Host_Discovery
│   ├── Nmap Scanning
│   ├── Ping Sweeps
│   ├── Port Enumeration
│   └── Service Detection
├── System_and_Log_Analysis
│   ├── Linux Authentication Logs
│   ├── Windows Sysmon Monitoring
│   └── auditd & Cross-Platform Log Monitoring
├── Packet_and_Traffic_Analysis
│   ├── Wireshark
│   ├── Zeek/Bro
│   ├── Suricata
│   └── tcpdump
├── Web_Security_Investigations
│   ├── Nikto Scans
│   ├── DVWA / Metasploitable Exploitation
│   └── Web Vulnerability Documentation
├── Threat_Hunting_and_Intelligence
│   ├── MITRE ATT&CK Mapping
│   ├── UEBA
│   ├── Cloud Threat Monitoring
│   └── Threat Intelligence Feed Integration
├── Incident_Response_and_Forensics
│   ├── Malware Analysis
│   ├── Root Cause Investigation
│   └── Multi-Stage Attack Reconstruction
├── SOC_Automation_and_AI
│   ├── SOAR Playbooks
│   ├── ML Anomaly Detection
│   └── Predictive Threat Modeling
└── Enterprise_Security_Leadership
    ├── SOC Architecture Design
    ├── Zero Trust Deployment
    ├── Red-Blue-Gold Team Operations
    └── Executive Dashboards & KPI Monitoring
</pre>

<hr>

<!-- Centered Tools Header -->
<div align="center">

## Tools & Environments Used

</div>

<!-- Left-aligned Tools Tree -->
<pre>
SOC_Tools/
├── Operating_Systems
│   ├── Kali Linux
│   ├── Ubuntu
│   ├── Windows Server
│   └── Metasploitable
├── Network_and_Vulnerability_Tools
│   ├── Nmap
│   ├── Netcat
│   ├── Zeek/Bro
│   ├── Suricata
│   └── Nikto
├── Packet_Analysis
│   ├── Wireshark
│   └── tcpdump
├── SIEM_and_Monitoring
│   ├── Splunk
│   ├── ELK Stack
│   └── Wazuh
├── Automation_and_Orchestration
│   ├── Cortex XSOAR
│   ├── Python
│   └── Shell Scripting
├── Forensics_and_Malware_Analysis
│   ├── Volatility
│   ├── Cuckoo Sandbox
│   ├── IDA Pro
│   └── Ghidra
└── Threat_Intelligence_Platforms
    ├── MISP
    ├── AlienVault OTX
    └── OSINT Feeds
</pre>

<hr>

<!-- Centered Portfolio Highlights Header -->
<div align="center">

## Portfolio Highlights

</div>

<!-- Beautiful Table for Highlights -->
<table align="center">
  <tr>
    <th>Category</th>
    <th>Key Skills Demonstrated</th>
    <th>Tools / Technologies</th>
  </tr>
  <tr>
    <td>Red-Blue-Gold Team Exercises</td>
    <td>Enterprise attack detection & response simulations</td>
    <td>Windows, Linux, Metasploitable, SIEM</td>
  </tr>
  <tr>
    <td>SOC Automation & AI Integration</td>
    <td>SOAR playbooks, ML anomaly detection, predictive modeling</td>
    <td>Cortex XSOAR, Python, Shell Scripting</td>
  </tr>
  <tr>
    <td>Threat Intelligence Correlation</td>
    <td>TI feeds correlated with SIEM and endpoint monitoring</td>
    <td>MISP, AlienVault OTX, ELK Stack, Wazuh</td>
  </tr>
  <tr>
    <td>Cross-Platform Threat Hunting</td>
    <td>Windows, Linux, and macOS analysis in hybrid environments</td>
    <td>Sysmon, auditd, Wireshark, tcpdump</td>
  </tr>
  <tr>
    <td>Enterprise Incident Response</td>
    <td>Multi-stage ransomware, insider threat, APT investigation</td>
    <td>Volatility, Cuckoo Sandbox, Splunk, ELK</td>
  </tr>
  <tr>
    <td>Zero Trust & Enterprise Security Design</td>
    <td>Micro-segmentation, MFA, continuous identity verification</td>
    <td>Windows AD, Linux PAM, MFA tools</td>
  </tr>
  <tr>
    <td>Executive Dashboards</td>
    <td>KPI monitoring for MTTR, MTTD, threat trends, asset risk</td>
    <td>Splunk, ELK Stack, Wazuh</td>
  </tr>
</table>

<hr>

<!-- Centered Footer -->
<div align="center">

This portfolio demonstrates both technical capability and strategic SOC leadership.  

</div>

