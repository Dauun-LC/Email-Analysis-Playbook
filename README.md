# Email Analysis Playbook

## Purpose
Provide a repeatable, modular workflow for investigating suspicious emails, validating sender authenticity, detecting phishing/spoofing, and determining appropriate response actions.

## Scope
* Email security investigations (phishing, spoofing, BEC)
* Header analysis and authentication validation
* Threat classification and risk scoring
* Incident response recommendations

## Playbook Metadata
**Playbook ID:** SOC-EML-001  
**Category:** Email Security / Phishing / Spoofing  
**Tier:** T1 → T3  
**MITRE ATT&CK:** T1566 (Phishing), T1586 (Compromise Accounts)

---

## Trigger Sources
* User-reported phishing
* Secure Email Gateway (SEG) alerts
* SIEM correlation rules
* VIP/Executive mailbox monitoring
* Suspicious login correlated with suspicious email
* Threat intel hit on sender IP/domain
* Abuse mailbox ingestion
* Automated anomaly detection (volume spikes, new sender patterns)

---

## Playbook Inputs

### Required
* `raw_headers` (full email headers)
* `recipient_email`
* `alert_source`

### Optional
* `email_body_html`
* `email_body_text`
* `reported_sender_context` (vendor, exec, internal, partner)
* `user_report_notes`
* `attachment_metadata` (filename, MIME type, hash)
* `link_list` (URLs extracted by SEG/SIEM)
* `seg_disposition` (allowed, quarantined, rewritten, bannered)

---

## Playbook Outputs
* `authenticity_status` (Authentic | Spoofed | Indeterminate)
* `threat_classification` (Legitimate | Suspicious | Phishing | BEC | Spam | Malware Delivery)
* `origin_attribution`
* `confidence_score` (0–100)
* `recommended_action`
* `ioc_list` (IPs, domains, URLs, hashes)
* `escalation_required` (Yes/No)

---

## Workflow Overview
```
Start
 ↓
Header Normalization
 ↓
Routing Reconstruction
 ↓
Authentication Evaluation
 ↓
Origin Attribution
 ↓
Spoofing & Impersonation Checks
 ↓
Content & Intent Analysis
 ↓
Phishing Risk Evaluation
 ↓
Security Signal Scoring
 ↓
Final Verdict & Action
End
```

---

## Investigation Modules

For detailed technical documentation of each module, see [docs/detection-modules.md](docs/detection-modules.md)

### Module 1: Header Normalization
* Extract and order `Received:` headers
* Normalize line folding (RFC 5322)
* Validate timestamp formats
* Extract envelope fields (`Return-Path`, `Message-ID`, `Reply-To`, `From`, `To`, `Date`)

**Output:** `received_chain[]`, `header_integrity_status`, `timestamp_anomalies`

### Module 2: Routing Reconstruction
* Identify true sending path
* Extract source IP, hostname, SMTP method, TLS version
* Detect private IP hops
* Flag reverse DNS mismatches

**Output:** `origin_ip`, `origin_asn`, `submission_type`, `transport_security`

### Module 3: Authentication Evaluation
* Parse SPF, DKIM, DMARC, ARC chain
* Validate alignment status
* Check DKIM selector reputation

**Authentication Decision Matrix:**
| SPF | DKIM | DMARC | Verdict |
|-----|------|--------|---------|
| pass | pass | pass | Strong |
| pass | pass | fail | Misaligned |
| fail | fail | fail | Spoofed |
| none | pass | none | Weak |

**Output:** `spf_result`, `dkim_result`, `dmarc_result`, `alignment_status`

### Module 4: Origin Attribution
* ASN lookup and classification
* Geo-IP lookup
* Hosting provider identification
* Threat intel enrichment

**Classification Logic:**
```
IF ASN in (Google, Microsoft) → Major ESP
ELSE IF ASN in (AWS, Azure, GCP) → Cloud Infrastructure
ELSE IF ASN is Residential → End User
ELSE IF ASN in known spam networks → High-Risk Infrastructure
ELSE → Unknown
```

**Output:** `origin_type`, `origin_geo`, `origin_risk_level`, `ti_hits`

### Module 5: Spoofing & Impersonation Detection
* From vs Return-Path mismatch
* DKIM domain vs From domain comparison
* Lookalike domain detection (Levenshtein distance ≤ 2)
* Homoglyph detection
* Display-name impersonation
* Reply-To mismatch
* VIP impersonation rules

**Spoofing Logic:**
```
IF dmarc_result == fail AND from_domain == protected_domain → Confirmed Spoofing
ELSE IF lookalike_domain == true → Suspected Impersonation
ELSE IF reply-to != from → Suspicious
ELSE → No Spoofing Detected
```

**Output:** `spoofing_status`, `impersonation_type`

### Module 6: Content & Intent Analysis
* NLP keyword extraction (finance, urgency, credentials)
* Link analysis (redirect chains, URL shorteners)
* Attachment analysis (file type, macros, executable content)
* Brand impersonation detection
* Language anomalies (grammar, tone, locale mismatch)
* Behavioral anomalies (new sender contacting exec)

**Output:** `intent_category`, `content_risk_score`

### Module 7: Phishing Risk Evaluation

**Risk Indicators (weighted scoring):**
| Indicator | Weight |
|----------|--------|
| External sender claiming to be internal | +25 |
| Financial/credential request | +25 |
| Urgency language | +15 |
| Suspicious links | +25 |
| Attachment with macros | +30 |
| Reply-To mismatch | +15 |
| Brand impersonation | +20 |
| New sender contacting VIP | +20 |
| Language mismatch | +10 |

**Output:** `phishing_score`, `phishing_confidence`

### Module 8: Security Signal Scoring

**Aggregate risk scoring based on:**
* Authentication strength
* Origin trust level
* Spoofing status
* Phishing indicators
* Transport security
* Threat intel hits
* Behavioral anomalies

**Sample Scoring Logic:**
```
confidence_score = 100
-30 if DMARC fail
-20 if unauthenticated submission
-15 if cloud infrastructure + consumer mailbox
-25 if impersonation detected
-20 if suspicious links
-30 if malicious attachment
-10 if timestamp anomalies
+10 if DKIM strong + ARC intact
```

### Module 9: Final Verdict Engine

**Verdict Classification:**
| Conditions | Verdict |
|-----------|---------|
| Strong auth + low phishing score | Legitimate |
| Weak auth + no phishing indicators | Suspicious |
| DMARC fail + impersonation | Phishing |
| Exec target + finance theme | BEC |
| Malicious attachment detected | Malware Delivery |
| High threat intel hits | Phishing/Malware |

### Module 10: Response Actions

**Verdict-Based Actions:**
| Verdict | Action |
|---------|--------|
| Legitimate | Close alert, document findings |
| Suspicious | Monitor, warn user, flag for review |
| Phishing | Quarantine email, block IOCs, notify user |
| BEC | Escalate to IR, reset credentials, preserve evidence |
| Malware Delivery | Quarantine, sandbox analysis, block IOCs, scan endpoints |

---

## Quick Reference: Tier 1 Analyst Checklist

*60-second triage for frontline analysts*

### 1. Check Authentication
- [ ] SPF/DKIM/DMARC all pass? → **Low risk**
- [ ] Any authentication failures? → **Medium/High risk**

### 2. Check Sender Origin
- [ ] IP from major ESP (Google, Microsoft)?
- [ ] Cloud infrastructure?
- [ ] Residential ISP?
- [ ] Threat intel hits?

### 3. Check for Spoofing
- [ ] From ≠ Return-Path?
- [ ] Lookalike domain?
- [ ] Reply-To mismatch?
- [ ] VIP impersonation attempt?

### 4. Check Content
- [ ] Suspicious links present?
- [ ] Attachments (especially with macros)?
- [ ] Urgency language?
- [ ] Financial/credential requests?

### 5. Quick Risk Score
```
Start at 100
-30 DMARC fail
-20 unauthenticated submission
-25 impersonation detected
-25 suspicious links
-30 malicious attachment
```

### 6. Determine Verdict
* **>80** → Likely Legitimate
* **50-80** → Suspicious
* **<50** → Phishing/BEC/Malware

### 7. Take Action
* **Legitimate** → Close alert
* **Suspicious** → Warn user
* **Phishing** → Quarantine + block IOCs
* **BEC** → Escalate to IR team

---









