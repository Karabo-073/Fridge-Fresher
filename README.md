<!-- Cybersecurity Portfolio README -->

<div align="center" style="font-family: Arial, sans-serif; line-height: 1.6;">

<u><h1>Web Application Penetration Testing Portfolio – DVWA Lab</h1></u>

<br>

This portfolio presents a structured, hands-on penetration testing project conducted on a controlled DVWA (Damn Vulnerable Web Application) lab environment. 
It demonstrates practical skills in reconnaissance, vulnerability assessment, and exploitation using industry-standard tools and methodologies. 
The project reflects a real-world approach to identifying security weaknesses while adhering to ethical hacking principles and safe testing practices.

<br><br>

<u><h2>Portfolio Structure (Tree Diagram)</h2></u>

<pre>
DVWA_Penetration_Testing_Project/
│
├── Part_1_Reconnaissance
│     ├── Manual Discovery (robots.txt, HTTP headers)
│     ├── Technology Fingerprinting (Wappalyzer)
│     ├── Port Scanning (Nmap)
│     └── Directory Enumeration (ffuf, Gobuster, Dirb)
│
├── Part_2_Vulnerability_Assessment
│     ├── Web Server Scanning (Nikto)
│     ├── Misconfiguration Analysis
│     └── Identification of Security Weaknesses
│
└── Part_3_Exploitation
      ├── Exploitation of Identified Vulnerabilities
      ├── Proof of Concept (PoC)
      └── Impact Analysis & Documentation
</pre>

<br>

<u><h2>Tools & Technologies Used</h2></u>

<table border="1" cellpadding="8" cellspacing="0" align="center">
<tr>
<th>Category</th>
<th>Tools</th>
<th>Purpose</th>
</tr>
<tr>
<td>Operating System</td>
<td>Kali Linux</td>
<td>Penetration testing environment</td>
</tr>
<tr>
<td>Reconnaissance Tools</td>
<td>Nmap, Wappalyzer, curl</td>
<td>Port scanning, service detection, technology identification</td>
</tr>
<tr>
<td>Web Scanning</td>
<td>Nikto</td>
<td>Identify vulnerabilities and misconfigurations</td>
</tr>
<tr>
<td>Content Discovery</td>
<td>ffuf, Gobuster, Dirb</td>
<td>Directory and file enumeration</td>
</tr>
<tr>
<td>Web Application</td>
<td>DVWA</td>
<td>Vulnerable lab environment for testing</td>
</tr>
</table>

<br>

<u><h2>Practical Labs – Highlights</h2></u>

<div align="center"><u>Reconnaissance & Information Gathering</u></div>
<pre>
Objective:
• Gather information about the target system and identify attack surface.

Techniques:
• Manual discovery (robots.txt, HTTP headers)
• Technology fingerprinting (Wappalyzer)
• Port scanning using Nmap
• Directory brute forcing using ffuf, Gobuster, and Dirb

Findings:
• Open ports and running services identified
• Web server: Apache (Debian)
• Exposed directories: /config/, /database/, /docs/, /tests/
• Sensitive files discovered (php.ini, robots.txt)
• Exposed .git repository files

Analysis:
• Large attack surface identified
• Misconfigurations and information disclosure risks present
</pre>

<div align="center"><u>Vulnerability Assessment</u></div>
<pre>
Objective:
• Identify vulnerabilities and misconfigurations within the web application.

Tools:
• Nikto web server scanner

Findings:
• Missing security headers (CSP, HSTS, etc.)
• Directory indexing enabled
• Exposed configuration and database directories
• Accessible administrative endpoints

Analysis:
• Weak security configurations increase risk of exploitation
• Sensitive data exposure possible through misconfigured directories
</pre>

<div align="center"><u>Exploitation & Impact</u></div>
<pre>
Objective:
• Exploit identified vulnerabilities in a controlled environment.

Activities:
• Exploitation of exposed directories and files
• Analysis of .git repository exposure
• Validation of vulnerabilities through proof-of-concept testing

Findings:
• Sensitive information disclosure confirmed
• Potential access to internal application structure

Analysis:
• Demonstrates real-world attack scenarios
• Highlights importance of secure configurations and access controls
</pre>

<br>

<u><h2>Professional Summary</h2></u>

This project demonstrates practical cybersecurity skills including:

• Web application reconnaissance and attack surface mapping  
• Port scanning and service enumeration  
• Automated directory and file discovery  
• Vulnerability identification and analysis  
• Ethical exploitation in a controlled lab environment  
• Structured documentation following penetration testing methodology  

<br><br>

<div align="center"><u>Portfolio</u></div>

</div>
