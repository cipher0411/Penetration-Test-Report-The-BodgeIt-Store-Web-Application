# Penetration Test Report: The BodgeIt Store Web Application

## Executive Summary

This report provides detailed findings and actionable recommendations from the penetration test conducted on **The BodgeIt Store** web application. The goal of this evaluation was to identify application flaws, configuration errors, and vulnerabilities; assess their risk levels; and propose measures to mitigate them.

The assessment followed the **NIST methodology** and included scanning, analyzing, and exploiting vulnerabilities. This report highlights the critical vulnerabilities discovered, their risk levels, and practical steps to enhance the security posture of the application.

---

## Key Findings

### Open Ports and Vulnerabilities

The following ports were identified as vulnerable:

- **SSH**
- **HTTP**
- **HTTPS**
- **IMAP**
- **Microsoft-AD**
- **HTTP-Proxy**
- **NetBIOS-SSN**

### Common Issues

1. **Open HTTP Port**

   - **Risk**: Potential data interception, server compromise, and application attacks.
   - **Recommendations**:
     - Implement **HTTPS** to encrypt data transfers.
     - Enable **Security Headers** (e.g., HSTS, X-Frame-Options, CSP).
     - Regularly **patch and update** web server software.
     - Deploy a **Web Application Firewall (WAF)**.
    
![image](https://github.com/user-attachments/assets/a6be4e12-4c43-495b-b717-a290bba47932)


2. **Open HTTPS Port**

   - **Risk**: SSL/TLS vulnerabilities, weak encryption, and certificate issues.
   - **Recommendations**:
     - Enforce robust encryption protocols (e.g., TLS 1.2+).
     - Use proper certificate management practices.
     - Enable **HSTS** to prevent SSL stripping attacks.

---

## Bash Commands for Vulnerability Discovery and Mitigation

### Discovering Vulnerabilities

#### Port Scanning

```bash
# Scan all ports and services on the target IP
nmap -sV -p- 192.168.1.100
```

#### Web Application Vulnerability Scanning

```bash
# Use Nikto to scan web server vulnerabilities
nikto -h http://192.168.1.100
```

#### SSL/TLS Analysis

```bash
# Test SSL/TLS configurations
sslscan 192.168.1.100
```

#### Enumerating HTTP Methods

```bash
# Check for HTTP methods enabled on the server
curl -X OPTIONS http://192.168.1.100 -I
```

### Exploiting Vulnerabilities

#### Exploiting OpenSSL SSL/TLS MITM (CVE-2014-0224)

```bash
# Run an exploit to demonstrate vulnerability (ethical purpose only)
msfconsole -q -x "use auxiliary/scanner/http/openssl_ccs; set RHOSTS 192.168.1.100; run"
```
![image](https://github.com/user-attachments/assets/096e3912-81f2-4de8-8179-7288c93abe43)

#### Testing SQL Injection Vulnerability

```bash
# Use sqlmap to identify SQL injection points
sqlmap -u "http://192.168.1.100/product.php?id=1" --dbs
```

### Mitigation Commands

#### Disabling Outdated SSL/TLS Versions

```bash
# Edit Apache SSL configuration file
sudo nano /etc/apache2/sites-available/default-ssl.conf

# Add/Update the following lines:
SSLProtocol -SSLv3 -TLSv1
SSLCipherSuite HIGH:!aNULL:!MD5

# Restart Apache
sudo systemctl restart apache2
```

#### Applying Security Headers

```bash
# Add security headers to the web server configuration
sudo nano /etc/apache2/conf-enabled/security.conf

# Add the following lines:
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set Content-Security-Policy "default-src 'self'"

# Restart Apache
sudo systemctl restart apache2
```

---

## Nexpose Vulnerability Scan Results

### Vulnerability Overview

- **Total Vulnerabilities**: 686
  - Critical: 158
  - Severe: 502
  - Moderate: 26

### Common Vulnerabilities

1. **Apache HTTPD: Range Header Remote DoS (CVE-2011-3192)**

   - **Risk Rating**: Critical (CVSS: 7.8)
   - **Recommendation**: Upgrade to the latest Apache HTTPD version.

2. **OpenSSL SSL/TLS MITM (CVE-2014-0224)**

   - **Risk Rating**: Severe (CVSS: 5.8)
   - **Recommendation**: Upgrade OpenSSL to version 0.9.8za.

3. **Cross-Site Request Forgery (CSRF)**

   - **Risk Rating**: Severe (CVSS: 4.3)
   - **Recommendation**: Implement robust CSRF protection mechanisms.

---

## Technical Summary

| **Vulnerability**                     | **Description**                                                           | **Risk Rating** | **CVSS** | **Recommendations**                           |
| ------------------------------------- | ------------------------------------------------------------------------- | --------------- | -------- | --------------------------------------------- |
| Apache HTTPD: Range Header Remote DoS | Causes excessive memory and CPU usage via crafted Range headers.          | Critical        | 7.8      | Upgrade Apache HTTPD to the latest version.   |
| OpenSSL SSL/TLS MITM                  | Man-in-the-middle attack through improper ChangeCipherSpec processing.    | Severe          | 5.8      | Upgrade OpenSSL to version 0.9.8za.           |
| TLS/SSL Server POODLE Attack          | Exploits SSL 3.0 vulnerabilities to decrypt session data.                 | Critical        | 7.3      | Disable SSL 3.0 and enforce TLS 1.2+.         |
| HTTP TRACE Method Enabled             | Can lead to Cross-Site Scripting attacks by echoing HTTP request headers. | Severe          | 5.2      | Disable TRACE method in Apache configuration. |
| Improper sanitization in WP\_Query    | SQL injection risk through improper sanitization in WordPress queries.    | Critical        | 7.2      | Enable auto-updates and sanitize all queries. |

---

## Visual Representations

### Vulnerability Severity Breakdown

![image](https://github.com/user-attachments/assets/6b10cde9-90f7-4c98-9073-4b8a7dfa24bc)
![image](https://github.com/user-attachments/assets/57d651bb-358b-493b-a6ea-4d568c25bf6b)


### Nmap Scan Output Example



### SSL/TLS Scan Output Example



---

## Recommendations

1. **Security Hardening**

   - Transition all HTTP connections to **HTTPS**.
   - Use robust **SSL/TLS protocols** and disable outdated versions.
   - Regularly patch servers and applications.

2. **Application Monitoring**

   - Deploy a **Web Application Firewall (WAF)**.
   - Perform periodic vulnerability assessments.

3. **User Awareness**

   - Train users on security best practices.
   - Implement multi-factor authentication (MFA) for administrative access.

---

## Tools Used

- **Nexpose Vulnerability Scanner**: For identifying and categorizing vulnerabilities.
- **Nmap**: For port scanning and service enumeration.
- **Nikto**: For web application vulnerability scanning.
- **sqlmap**: For testing SQL injection vulnerabilities.

---

## Conclusion

The BodgeIt Store's web application contains critical vulnerabilities that require immediate attention to mitigate the risks of exploitation. Implementing the provided recommendations will significantly enhance the security posture of the application.

---

For any questions or further assistance, please contact the security team.

write me the readme code to post on github

