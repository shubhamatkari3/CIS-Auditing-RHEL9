# CIS Audit Implementation for RHEL-9

CIS (Center for Internet Security) Audit for RHEL-9 involves assessing the security configuration of Red Hat Enterprise Linux 9 systems against a set of benchmark standards provided by CIS. This audit helps ensure compliance with industry best practices and security standards, identifying and remediating vulnerabilities to enhance the overall security posture of RHEL-9 environments.


**Steps to initialize the audit:**

1. Copy the repository link: https://github.com/shubhamatkari3/CIS-Hardening.git
   
3. Log in to your RHEL-9 system as the root user.
   
5. If Git is not installed on your RHEL-9 system, install it using the command: dnf install git -y
   
7. Clone the repository using the command: git clone https://github.com/shubhamatkari3/CIS-Hardening.git
   
9. Navigate into the cloned directory by using the command: cd CIS-Hardening
    
11. Make the script executable by running the command: chmod +x RHEL9-CIS-AUDIT.sh
    
13. Execute the script by running the command: ./RHEL9-CIS-AUDIT.sh to start the audit.
