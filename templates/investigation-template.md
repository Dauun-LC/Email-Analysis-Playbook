# Email Investigation Template

# Email Investigation Report

**Case ID:** [AUTO-GENERATED or MANUAL]  
**Analyst:** [Your Name]  
**Date/Time:** [YYYY-MM-DD HH:MM UTC]  
**Alert Source:** [User Report | SEG Alert | SIEM | Other]  
**Priority:** [Low | Medium | High | Critical]

---

## Executive Summary

**Verdict:** [Legitimate | Suspicious | Phishing | BEC | Malware Delivery | Spam]  
**Confidence:** [Low | Medium | High]  
**Action Taken:** [Delivered | Quarantined | Blocked | Escalated]  
**Risk to Organization:** [None | Low | Medium | High]

**One-line summary:**  
[Brief description of what this email was and what action was taken]

---

## Email Metadata

### Basic Information
* **Subject:** 
* **From (Display Name):** 
* **From (Email Address):** 
* **Reply-To:** 
* **Return-Path:** 
* **To:** 
* **Date Sent:** 
* **Message-ID:** 

### Recipient Context
* **Recipient Role:** [Employee | VIP | Executive | IT | Finance | Other]
* **User Action:** [Reported | Clicked Link | Opened Attachment | Replied | None]
* **Business Impact:** [None | Potential Data Exposure | Financial Loss Risk | Credential Compromise]

---

## Technical Analysis

### Module 1: Header Analysis

**Received Chain Summary:**
* **Total Hops:** 
* **Origin IP:** 
* **Origin Hostname:** 
* **Submission Type:** [Authenticated | Unauthenticated | Unknown]
* **Transport Security:** [TLS 1.3 | TLS 1.2 | TLS 1.1 | None]

**Header Integrity:**
* **Status:** [Intact | Degraded | Missing Critical Headers]
* **Timestamp Anomalies:** [Yes | No]
* **Clock Skew:** [None | X minutes/hours]

---

### Module 2: Authentication Results

**SPF:**
* **Result:** [pass | fail | softfail | neutral | none]
* **Aligned:** [Yes | No]
* **Details:** 

**DKIM:**
* **Result:** [pass | fail | none]
* **Signing Domain:** 
* **Aligned:** [Yes | No]
* **Details:** 

**DMARC:**
* **Result:** [pass | fail | none]
* **Policy:** [none | quarantine | reject]
* **Details:** 

**Authentication Score:** [0-100]

---

### Module 3: Origin Attribution

**Infrastructure:**
* **ASN:** 
* **Organization:** 
* **Country:** 
* **Classification:** [Major ESP | Cloud | Residential | High-Risk | Unknown]

**Threat Intelligence:**
* **AbuseIPDB Score:** [0-100]
* **VirusTotal Detections:** [X/90]
* **Other TI Hits:** 
* **Previous Emails from this IP:** [First time | X previous emails]

**Origin Risk Level:** [Low | Medium | High]

---

### Module 4: Spoofing & Impersonation Analysis

**Spoofing Status:** [None | Suspected | Confirmed]

**Checks Performed:**
- [ ] From vs Return-Path mismatch
- [ ] Lookalike domain detection
- [ ] Homoglyph detection
- [ ] Display name impersonation
- [ ] Reply-To mismatch
- [ ] VIP impersonation attempt

**Findings:**
* **Impersonation Type:** [None | Domain | Display Name | Reply-To | VIP]
* **Target:** [Organization/Person being impersonated]
* **Lookalike Domain:** 
* **Legitimate Domain:** 

---

### Module 5: Content Analysis

**Email Body Summary:**
[Brief description of email content and stated purpose]

**Intent Classification:** [Financial | Credential Theft | Malware Delivery | Marketing | Spam]

**Keyword Analysis:**
- [ ] Financial keywords (invoice, payment, wire transfer)
- [ ] Credential keywords (verify, login, password reset)
- [ ] Urgency keywords (immediate, urgent, expires)
- [ ] Authority keywords (CEO, CFO, IT Department)
- [ ] Threat keywords (suspended, locked, legal action)

**Content Risk Score:** [0-100]

---

### Module 6: Link Analysis

**Total Links:** [X]

| URL | Display Text | Final Destination | Reputation | Risk |
|-----|--------------|-------------------|------------|------|
| | | | | |
| | | | | |

**Link Findings:**
- [ ] URL shorteners detected
- [ ] Display text mismatch
- [ ] Redirect chains present
- [ ] Malicious links confirmed
- [ ] Suspicious domains

---

### Module 7: Attachment Analysis

**Total Attachments:** [X]

| Filename | Type | Size | Hash (SHA256) | Reputation | Risk |
|----------|------|------|---------------|------------|------|
| | | | | | |
| | | | | | |

**Attachment Findings:**
- [ ] Dangerous file types (.exe, .scr, .bat)
- [ ] Macro-enabled documents
- [ ] Macros detected
- [ ] Extension mismatch
- [ ] Known malware hash
- [ ] Password-protected archives

---

## Risk Scoring

### Phishing Risk Score: [0-100]

**Contributing Factors:**
* [Factor 1]: +X points
* [Factor 2]: +X points
* [Factor 3]: -X points

**Confidence Score:** [0-100]

---

## Indicators of Compromise (IOCs)

**IP Addresses:**
```
[List IPs]
```

**Domains:**
```
[List domains]
```

**URLs:**
```
[List full URLs]
```

**File Hashes:**
```
SHA256: [hash]
SHA256: [hash]
```

**Email Addresses:**
```
[List email addresses]
```

---

## Response Actions

### Immediate Actions Taken
- [ ] Email quarantined
- [ ] User notified
- [ ] Sender blocked
- [ ] IOCs blocked at perimeter
- [ ] Similar emails searched and removed
- [ ] Endpoint scan initiated
- [ ] Credentials reset

### Follow-up Actions Required
- [ ] Create detection rule
- [ ] Update security awareness training
- [ ] Escalate to IR team
- [ ] Notify executives
- [ ] Report to authorities
- [ ] Update threat intel feeds

### User Communication
**Notification Sent:** [Yes | No]  
**Message:** [Brief summary of what was communicated to user]

---

## Timeline

| Time (UTC) | Event |
|------------|-------|
| [HH:MM] | Email received |
| [HH:MM] | User reported/Alert triggered |
| [HH:MM] | Investigation started |
| [HH:MM] | Email quarantined |
| [HH:MM] | IOCs blocked |
| [HH:MM] | Investigation completed |

**Total Time to Resolution:** [X minutes/hours]

---

## Lessons Learned

**What Worked Well:**
* 

**What Could Be Improved:**
* 

**Detection Gaps Identified:**
* 

**Recommendations:**
* 

---

## Validation Checklist

Investigation Completeness:
- [ ] Authentication results verified
- [ ] Origin infrastructure analyzed
- [ ] Spoofing checks completed
- [ ] Content analyzed for threats
- [ ] Links inspected and rated
- [ ] Attachments analyzed (if present)
- [ ] Threat intel consulted
- [ ] Risk score calculated
- [ ] IOCs extracted and documented
- [ ] Appropriate response action taken
- [ ] User notified (if required)
- [ ] Similar emails searched for
- [ ] Case documented in ticketing system

---

## Appendix

### Raw Email Headers
```
[Paste full headers here for reference]
```

### Screenshots
[Attach any relevant screenshots of email content, links, or analysis tools]

### Related Cases
* **Case ID:** [Related case]
* **Case ID:** [Related case]

### External References
* **Threat Intel Report:** [Link]
* **Similar Campaign:** [Link]

---

## Approvals & Sign-off

**Reviewed By:** [Senior Analyst Name]  
**Date:** [YYYY-MM-DD]  
**Status:** [Open | Closed | Escalated]

---

**Report Generated:** [YYYY-MM-DD HH:MM UTC]  
**Playbook Version:** 1.0  
**Template Version:** 1.0
