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
├── Part_2_Vulnerability_Analysis
│     ├── Missing Security Headers (Nikto)
│     ├── Directory Indexing Enabled (/config/, /database/, /tests/)
│     ├── Exposed .git Repository (ffuf / Gobuster)
│     ├── Sensitive Files Exposed (php.ini, phpinfo.php)
│     ├── Multiple Open Ports (Nmap)
│     ├── Outdated Server Version (Apache 2.4.66)
│     └── Username Enumeration (Manual Testing)
│
└── Part_3_Exploitation
      ├── Exploit SQL Injection
      ├── Exploit XSS
      └── Exploit File Inclusion / Misconfigurations
</pre>

<br>

<u><h2>Part 1 – Reconnaissance</h2></u>

This phase focused on **information gathering and surface mapping** of the DVWA application. The goal was to understand the web application structure, identify technologies, and map potential attack surfaces in a **controlled lab environment**.

**Key Activities:**
- **Manual Discovery:** robots.txt, sitemap.xml, HTTP headers  
- **Technology Fingerprinting:** Wappalyzer (PHP, Apache, MySQL/MariaDB)  
- **Port Scanning:** Nmap to identify open ports and running services  
- **Directory / File Enumeration:** ffuf, Gobuster, Dirb to discover hidden directories, files, and resources  

**Summary of Findings:**  
- Robots.txt restricted indexing but revealed sensitive paths  
- HTTP headers exposed Apache 2.4.66 and PHP session cookies  
- Open ports identified: 80 (HTTP), 3306 (MySQL), 8089, 8191  
- Multiple directories and sensitive files exposed for further analysis  

*Screenshots: Figure 1.1 – 1.6*

<br>

<u><h2>Part 2 – Vulnerability Analysis</h2></u>

This phase analyzed the DVWA web application for **security weaknesses** based on reconnaissance findings. Evidence, risk, and remediation recommendations were recorded for each vulnerability.

| Vulnerability | Location | Evidence | Risk / Impact |
| --- | --- | --- | --- |
| Missing Security Headers | Web Server (Apache) | Nikto Scan – Screenshot 2.1 | Medium – Increases risk of XSS, MITM, clickjacking |
| Directory Indexing Enabled | `/config/`, `/database/`, `/tests/` | Nikto / Dirb – Screenshot 2.2 | High – Sensitive files exposed |
| Exposed `.git` Repository | `/.git/` | ffuf / Gobuster – Screenshot 2.3 | High – Source code disclosure |
| Sensitive Files Exposed | `php.ini`, `phpinfo.php` | ffuf – Screenshot 2.4 | High – System configuration leakage |
| Multiple Open Ports | 80, 3306, 8089, 8191 | Nmap Scan – Screenshot 2.5 | Medium – Expanded attack surface |
| Outdated/Identified Server Version | Apache 2.4.66 (Debian) | HTTP Headers – Screenshot 2.6 | Medium – Known exploit potential |
| Username Enumeration | Login Page | Manual Testing – Screenshot 2.7 | Low-Medium – Enables targeted attacks |

**Evidence Highlights:**  
- Screenshots illustrate exposed directories, files, `.git` repository, server headers, and login responses.  
- Username enumeration confirmed by repeated login attempts with no restrictions.

**Remediation Recommendations:**  
- Implement security headers: CSP, HSTS, X-Frame-Options  
- Disable directory listing or restrict access  
- Restrict access to sensitive files and `.git` directories  
- Hide server version information  
- Implement account lockout, rate limiting, and generic login error messages  

*Screenshots: Figure 2.1 – 2.7*

<br>

<u><h2>Next Steps / Part 3 – Exploitation</h2></u>

Following vulnerability analysis, the **exploitation phase** will demonstrate practical application of penetration testing techniques:  
- Exploit SQL Injection, XSS, and File Inclusion vulnerabilities  
- Test configuration weaknesses in Apache and PHP  
- Document impact and evidence in a controlled environment  

*Screenshots and demonstration results will be included in Part 3.*

<br>

<u><h2>Conclusion</h2></u>

This portfolio demonstrates a **structured, hands-on approach to web application penetration testing**:  
1. **Reconnaissance:** Map application, identify technologies, and open services  
2. **Vulnerability Analysis:** Identify weaknesses, evaluate impact, and suggest mitigations  
3. **Exploitation:** Safely test vulnerabilities in a controlled lab  

The project showcases **practical cybersecurity skills** that are applicable to real-world penetration testing, ethical hacking, and web security assessments.  

</div>
