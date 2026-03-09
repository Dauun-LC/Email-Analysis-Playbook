# Detection Modules - Technical Reference

This document provides detailed technical specifications for each investigation module in the Email Analysis Playbook.

---

## Module 1: Header Normalization

### Purpose
Prepare raw email headers for consistent parsing and analysis.

### Technical Actions

#### 1. Extract Received Headers
```
FOR each line in raw_headers:
    IF line starts with "Received:":
        append to received_chain[]
```

#### 2. Normalize Line Folding
* Handle RFC 5322 folded headers (continuation lines starting with whitespace)
* Concatenate multi-line headers into single logical lines
* Preserve original structure for forensic purposes

#### 3. Order Received Headers
* Order from bottom (earliest/origin) to top (most recent/destination)
* Index 0 = origin server
* Index N = receiving mail server

#### 4. Extract Envelope Fields
```
Extract and store:
- Return-Path
- Message-ID
- Reply-To
- From (display name and email)
- To
- Date
- Subject
- X-Originating-IP (if present)
```

#### 5. Validate Timestamps
```
FOR each Received header:
    Extract timestamp
    Parse to UTC
    Calculate time delta between hops
    IF delta < 0 OR delta > 24 hours:
        FLAG timestamp_anomaly
```

### Output Variables
* `received_chain[]` - Ordered array of Received headers
* `header_integrity_status` - "intact" | "degraded" | "missing"
* `timestamp_anomalies` - Boolean flag
* `clock_skew` - Time difference between hops (in seconds)

### Edge Cases
* **Missing Received headers**: Flag as degraded, proceed with available data
* **Malformed timestamps**: Flag anomaly, use fallback Date header
* **Duplicate headers**: Keep all instances, note in forensic log

---
## Module 2: Routing Reconstruction

### Purpose
Identify the true origin of the email and map the delivery path.

### Technical Actions

#### 1. Identify Origin Server
```
origin_header = received_chain[0]  # First/lowest Received header

PARSE origin_header FOR:
- from [hostname] ([IP])
- by [receiving_server]
- with [SMTP_method]
- id [message_id]
- for [recipient]
```

#### 2. Extract Source IP
```
REGEX: \[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]
OR
REGEX: \[([0-9a-fA-F:]+)\]  # IPv6
```

#### 3. Classify Submission Type
```
IF smtp_method contains "ESMTPSA":
    submission_type = "Authenticated"
ELSE IF smtp_method contains "ESMTPS":
    submission_type = "Encrypted_Unauthenticated"
ELSE IF smtp_method contains "ESMTP":
    submission_type = "Unauthenticated"
ELSE:
    submission_type = "Unknown"
```

#### 4. Extract Transport Security
```
PARSE for:
- TLS version (TLS1.2, TLS1.3)
- Cipher suite
- Certificate validation status

IF TLS version < 1.2:
    FLAG tls_downgrade_risk
```

#### 5. Detect Private IP Hops
```
FOR each hop in received_chain:
    IF IP in (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16):
        IF previous_hop is public IP:
            FLAG internal_relay
        ELSE:
            FLAG suspicious_nat
```

#### 6. Reverse DNS Validation
```
PERFORM reverse DNS lookup on origin_ip
IF rdns_hostname != claimed_hostname:
    reverse_dns_mismatch = TRUE
```

### Output Variables
* `origin_ip` - First external IP in chain
* `origin_hostname` - Claimed sending hostname
* `origin_asn` - Autonomous System Number
* `submission_type` - Classification of submission method
* `transport_security` - TLS version and cipher
* `reverse_dns_mismatch` - Boolean flag
* `helo_domain` - Domain claimed in HELO/EHLO

### Detection Logic
```
IF submission_type == "Unauthenticated" 
AND origin_asn NOT IN trusted_esps:
    FLAG high_risk_origin

IF reverse_dns_mismatch == TRUE
AND submission_type == "Unauthenticated":
    FLAG spoofing_indicator
```

---
## Module 3: Authentication Evaluation

### Purpose
Validate email authentication mechanisms to determine sender legitimacy.

### Technical Actions

#### 1. Parse SPF Result
```
SEARCH headers for "Received-SPF:"
EXTRACT result: pass | fail | softfail | neutral | none | temperror | permerror

IF result == "pass":
    spf_aligned = (envelope_from_domain == header_from_domain)
```

#### 2. Parse DKIM Result
```
SEARCH headers for "DKIM-Signature:"
FOR each DKIM signature:
    EXTRACT:
    - d= (signing domain)
    - s= (selector)
    - a= (algorithm)
    - b= (signature hash)

SEARCH for "Authentication-Results:"
EXTRACT dkim= result

IF dkim == "pass":
    dkim_aligned = (signing_domain == header_from_domain)
```

#### 3. Parse DMARC Result
```
SEARCH for "Authentication-Results:"
EXTRACT dmarc= result

PARSE DMARC policy:
- p= (policy: none | quarantine | reject)
- pct= (percentage)
- rua= (aggregate reporting address)
```

#### 4. Validate ARC Chain
```
IF "ARC-Authentication-Results:" present:
    FOR each ARC set (i=1, i=2, ...):
        VALIDATE chain integrity
        IF break detected:
            FLAG arc_chain_broken
```

#### 5. Alignment Check
```
alignment_status = {
    "spf_aligned": envelope_from_domain == header_from_domain,
    "dkim_aligned": dkim_signing_domain == header_from_domain,
    "dmarc_pass": (spf_aligned OR dkim_aligned) AND dmarc == "pass"
}
```

### Authentication Decision Matrix

| SPF | DKIM | DMARC | Alignment | Verdict |
|-----|------|-------|-----------|---------|
| pass | pass | pass | both | **Strong Authentication** |
| pass | pass | fail | partial | Misaligned - Investigate |
| fail | fail | fail | none | **Spoofed** |
| none | pass | none | dkim only | Weak - Sender uses DKIM only |
| softfail | none | none | none | Weak - No authentication |
| pass | none | pass | spf only | Partial - SPF aligned |

### Output Variables
* `spf_result` - SPF check result
* `dkim_result` - DKIM verification result
* `dmarc_result` - DMARC policy evaluation
* `arc_result` - ARC chain validation
* `alignment_status` - Object with alignment flags
* `authentication_score` - Numeric score (0-100)

### Scoring Logic
```
score = 0

IF spf_result == "pass": score += 25
IF dkim_result == "pass": score += 35
IF dmarc_result == "pass": score += 40

IF spf_aligned: score += 10
IF dkim_aligned: score += 10

authentication_score = score
```

---

## Module 4: Origin Attribution

### Purpose
Contextualize the infrastructure used to send the email.

### Technical Actions

#### 1. ASN Lookup
```
QUERY ASN database for origin_ip
EXTRACT:
- asn_number
- asn_org
- asn_country
```

#### 2. Infrastructure Classification
```
IF asn_org IN ["GOOGLE", "MICROSOFT", "YAHOO"]:
    origin_type = "Major_ESP"
ELSE IF asn_org IN ["AMAZON-AES", "MICROSOFT-CORP-MSN-AS-BLOCK", "GOOGLE-CLOUD-PLATFORM"]:
    origin_type = "Cloud_Infrastructure"
ELSE IF asn_org contains "RESIDENTIAL" OR "BROADBAND":
    origin_type = "Residential_ISP"
ELSE IF asn_number IN known_spam_asns:
    origin_type = "High_Risk_Infrastructure"
ELSE:
    origin_type = "Unknown"
```

#### 3. Geo-IP Lookup
```
QUERY GeoIP database for origin_ip
EXTRACT:
- country
- region
- city
- coordinates
```

#### 4. Threat Intel Enrichment
```
QUERY threat intel feeds:
- AbuseIPDB (reputation score)
- VirusTotal (detection count)
- Talos (reputation category)
- Custom blocklists

ti_hits = {
    "abuseipdb_score": score,
    "vt_detections": count,
    "talos_category": category,
    "blocklist_hits": [list]
}
```

#### 5. Historical Analysis
```
QUERY email logs for:
- Previous emails from this IP
- Previous emails from this domain
- Frequency and pattern

IF first_seen:
    sender_novelty = TRUE
```

### Classification Logic
```
risk_level = "Low"

IF origin_type == "High_Risk_Infrastructure":
    risk_level = "High"
ELSE IF ti_hits["abuseipdb_score"] > 50:
    risk_level = "High"
ELSE IF origin_type == "Cloud_Infrastructure" AND submission_type == "Unauthenticated":
    risk_level = "Medium"
ELSE IF origin_type == "Residential_ISP":
    risk_level = "Medium"
ELSE IF origin_type == "Major_ESP" AND authentication_score > 75:
    risk_level = "Low"
```

### Output Variables
* `origin_type` - Infrastructure classification
* `origin_geo` - Geographic location object
* `origin_risk_level` - "Low" | "Medium" | "High"
* `ti_hits` - Threat intel results object
* `sender_novelty` - Boolean flag for new senders

---

## Module 5: Spoofing & Impersonation Detection

### Purpose
Detect attempts to impersonate legitimate senders or organizations.

### Technical Actions

#### 1. Envelope vs Header Comparison
```
envelope_from = Return-Path
header_from = From header

IF envelope_from != header_from:
    FLAG from_mismatch
    
    IF dmarc_result == "fail":
        spoofing_status = "Confirmed"
    ELSE:
        spoofing_status = "Suspected"
```

#### 2. Lookalike Domain Detection
```
FUNCTION calculate_levenshtein_distance(domain1, domain2):
    # Standard Levenshtein algorithm
    return edit_distance

FOR each protected_domain in organization_domains:
    distance = calculate_levenshtein_distance(sender_domain, protected_domain)
    
    IF distance <= 2:
        FLAG lookalike_domain
        lookalike_score = (2 - distance) * 50  # Higher score = closer match
```

#### 3. Homoglyph Detection
```
homoglyph_map = {
    'a': ['а', 'ɑ', 'α'],  # Cyrillic/Greek lookalikes
    'o': ['о', 'ο', '0'],
    'e': ['е', 'ε'],
    # ... full mapping
}

FOR each character in sender_domain:
    IF character in homoglyph_map.values():
        FLAG homoglyph_detected
```

#### 4. Display Name Impersonation
```
display_name = extract_display_name(From header)

FOR each vip in vip_list:
    IF display_name.lower() == vip.name.lower():
        IF sender_domain NOT IN vip.authorized_domains:
            FLAG display_name_impersonation
            impersonation_target = vip
```

#### 5. Reply-To Analysis
```
IF Reply-To header exists:
    IF Reply-To domain != From domain:
        FLAG reply_to_mismatch
        
        IF Reply-To domain in freemail_providers:
            FLAG reply_to_suspicious
```

#### 6. HELO Domain Validation
```
IF helo_domain != sending_domain:
    FLAG helo_mismatch
    
    IF helo_domain in ["localhost", "127.0.0.1", "unknown"]:
        FLAG helo_spoofing
```

### Spoofing Classification Logic
```
IF dmarc_result == "fail" AND from_domain == protected_domain:
    spoofing_status = "Confirmed"
    impersonation_type = "Domain_Spoofing"
    
ELSE IF lookalike_domain == TRUE:
    spoofing_status = "Suspected"
    impersonation_type = "Lookalike_Domain"
    
ELSE IF display_name_impersonation == TRUE:
    spoofing_status = "Suspected"
    impersonation_type = "Display_Name"
    
ELSE IF reply_to_mismatch == TRUE:
    spoofing_status = "Suspicious"
    impersonation_type = "Reply-To_Redirect"
    
ELSE:
    spoofing_status = "None_Detected"
```

### Output Variables
* `spoofing_status` - "Confirmed" | "Suspected" | "Suspicious" | "None_Detected"
* `impersonation_type` - Type of impersonation detected
* `lookalike_score` - Similarity score (0-100)
* `impersonation_target` - VIP/organization being impersonated
* `from_mismatch` - Boolean flag
* `reply_to_mismatch` - Boolean flag
---

## Module 6: Content & Intent Analysis

### Purpose
Analyze email body and attachments to determine sender intent and threat level.

### Technical Actions

#### 1. NLP Keyword Extraction
```
keyword_categories = {
    "financial": ["invoice", "payment", "wire transfer", "account", "bank", "urgent payment"],
    "credentials": ["verify account", "confirm password", "login", "reset password", "suspended"],
    "urgency": ["immediate", "urgent", "within 24 hours", "action required", "expires"],
    "authority": ["CEO", "CFO", "IT Department", "Security Team", "Manager"],
    "threats": ["account locked", "suspended", "legal action", "termination"]
}

FOR each category, keywords in keyword_categories:
    matches = count_matches(email_body, keywords)
    keyword_scores[category] = matches * weight
```

#### 2. Link Analysis
```
FOR each URL in email_body:
    # Extract and analyze
    parsed_url = parse_url(URL)
    
    # Check for URL shorteners
    IF parsed_url.domain IN url_shorteners:
        FLAG url_shortener_detected
        
    # Check for mismatched display text
    IF display_text != actual_url:
        FLAG url_text_mismatch
        
    # Follow redirect chain
    final_url = follow_redirects(URL)
    
    # Check against threat intel
    url_reputation = check_url_reputation(final_url)
    
    IF url_reputation == "malicious":
        FLAG malicious_link
```

#### 3. Attachment Analysis
```
FOR each attachment in email:
    file_info = {
        "filename": attachment.name,
        "mime_type": attachment.content_type,
        "size": attachment.size,
        "hash_md5": calculate_md5(attachment.data),
        "hash_sha256": calculate_sha256(attachment.data)
    }
    
    # Check file extension vs MIME type
    IF stated_extension != actual_mime_type:
        FLAG extension_mismatch
    
    # Check for dangerous file types
    IF extension IN [".exe", ".scr", ".bat", ".cmd", ".vbs", ".js"]:
        FLAG dangerous_filetype
    
    # Check for macro-enabled documents
    IF extension IN [".docm", ".xlsm", ".pptm"]:
        FLAG macro_document
        
        IF contains_macros(attachment.data):
            FLAG macros_detected
    
    # Threat intel hash lookup
    hash_reputation = check_file_hash(file_info["hash_sha256"])
```

#### 4. Brand Impersonation Detection
```
brand_indicators = {
    "microsoft": ["microsoft", "office365", "outlook", "teams"],
    "google": ["google", "gmail", "drive", "workspace"],
    "paypal": ["paypal", "payment"],
    # ... etc
}

FOR brand, keywords in brand_indicators:
    IF any(keyword in email_body.lower() OR keyword in subject.lower()):
        IF sender_domain NOT IN brand.authorized_domains:
            FLAG brand_impersonation
            impersonated_brand = brand
```

#### 5. Language Analysis
```
# Detect language mismatches
detected_language = detect_language(email_body)
expected_language = get_user_locale(recipient)

IF detected_language != expected_language:
    FLAG language_mismatch

# Grammar and spelling analysis
grammar_errors = count_grammar_errors(email_body)
spelling_errors = count_spelling_errors(email_body)

IF grammar_errors > threshold OR spelling_errors > threshold:
    FLAG poor_quality_writing
```

### Intent Classification Logic
```
intent_score = {
    "financial": 0,
    "credentials": 0,
    "malware": 0,
    "marketing": 0
}

# Score based on indicators
IF keyword_scores["financial"] > 3: intent_score["financial"] += 30
IF keyword_scores["credentials"] > 2: intent_score["credentials"] += 30
IF malicious_link OR dangerous_filetype: intent_score["malware"] += 40
IF url_shortener_detected AND urgency_keywords: intent_score["phishing"] += 25

# Determine primary intent
intent_category = max(intent_score, key=intent_score.get)
content_risk_score = intent_score[intent_category]
```

### Output Variables
* `intent_category` - "Financial" | "Credential_Theft" | "Malware_Delivery" | "Marketing" | "Spam" | "Unknown"
* `content_risk_score` - Numeric score (0-100)
* `keyword_scores` - Object with category scores
* `link_analysis` - Array of URL analysis results
* `attachment_analysis` - Array of attachment analysis results
* `impersonated_brand` - Brand being impersonated (if any)

---

## Module 7: Phishing Risk Evaluation

### Purpose
Aggregate indicators to calculate overall phishing risk.

### Weighted Scoring System
```python
phishing_score = 0

# Identity indicators
if spoofing_status == "Confirmed": phishing_score += 30
if lookalike_domain: phishing_score += 25
if display_name_impersonation: phishing_score += 20
if reply_to_mismatch: phishing_score += 15

# Content indicators
if intent_category == "Credential_Theft": phishing_score += 25
if intent_category == "Financial": phishing_score += 25
if keyword_scores["urgency"] > 2: phishing_score += 15
if brand_impersonation: phishing_score += 20

# Technical indicators
if malicious_link: phishing_score += 30
if dangerous_filetype: phishing_score += 25
if macros_detected: phishing_score += 30
if url_shortener_detected: phishing_score += 10

# Behavioral indicators
if sender_novelty AND vip_recipient: phishing_score += 20
if language_mismatch: phishing_score += 10
if poor_quality_writing: phishing_score += 10

# Authentication deductions
if authentication_score > 80: phishing_score -= 20
if origin_type == "Major_ESP": phishing_score -= 15

# Cap at 100
phishing_score = min(phishing_score, 100)
```

### Confidence Calculation
```python
confidence_factors = {
    "strong_authentication": authentication_score > 75,
    "confirmed_spoofing": spoofing_status == "Confirmed",
    "known_malicious": ti_hits["vt_detections"] > 5,
    "multiple_indicators": (malicious_link + dangerous_filetype + lookalike_domain) >= 2
}

confidence_score = 50  # Base confidence

if confidence_factors["strong_authentication"]: confidence_score += 20
if confidence_factors["confirmed_spoofing"]: confidence_score += 30
if confidence_factors["known_malicious"]: confidence_score += 30
if confidence_factors["multiple_indicators"]: confidence_score += 20

confidence_score = min(confidence_score, 100)
```

### Output Variables
* `phishing_score` - Risk score (0-100)
* `phishing_confidence` - Confidence in assessment (0-100)
* `contributing_factors` - Array of indicators that triggered

---

## Module 8: Security Signal Scoring

### Purpose
Create a composite security score from all available signals.

### Composite Scoring Algorithm
```python
security_signals = {
    "authentication": authentication_score * 0.25,
    "origin_trust": (100 - origin_risk_level_numeric) * 0.15,
    "spoofing": (100 - spoofing_confidence) * 0.20,
    "content": (100 - content_risk_score) * 0.20,
    "phishing": (100 - phishing_score) * 0.20
}

composite_score = sum(security_signals.values())

# Adjust for threat intel
if ti_hits["abuseipdb_score"] > 75:
    composite_score -= 30
if ti_hits["vt_detections"] > 10:
    composite_score -= 40

# Normalize to 0-100
composite_score = max(0, min(100, composite_score))
```

### Output Variables
* `composite_score` - Overall security score (0-100, higher = safer)
* `signal_breakdown` - Object showing individual signal contributions

---

## Module 9: Final Verdict Engine

### Purpose
Translate technical scores into actionable verdicts.

### Verdict Logic
```python
def determine_verdict(signals):
    # Critical indicators override everything
    if signals["malicious_link"] and signals["credentials_requested"]:
        return "Phishing"
    
    if signals["dangerous_filetype"] and signals["ti_hits"]["vt_detections"] > 5:
        return "Malware_Delivery"
    
    if signals["spoofing_status"] == "Confirmed" and signals["financial_request"]:
        return "BEC"
    
    # Score-based classification
    if signals["composite_score"] >= 80:
        return "Legitimate"
    elif signals["composite_score"] >= 50:
        return "Suspicious"
    elif signals["phishing_score"] >= 70:
        return "Phishing"
    elif signals["authentication_score"] < 30 and signals["origin_type"] == "High_Risk":
        return "Spam"
    else:
        return "Unknown_Needs_Review"
```

### Output Variables
* `final_verdict` - Classification result
* `verdict_confidence` - Confidence in verdict (0-100)
* `escalation_required` - Boolean flag

---

## Module 10: Response Actions

### Purpose
Map verdicts to specific response actions.

### Action Matrix
```python
response_actions = {
    "Legitimate": {
        "action": "deliver",
        "notify_user": False,
        "quarantine": False,
        "block_sender": False,
        "create_ticket": False
    },
    "Suspicious": {
        "action": "deliver_with_banner",
        "notify_user": True,
        "quarantine": False,
        "block_sender": False,
        "create_ticket": True,
        "banner_text": "This email appears suspicious. Exercise caution with links and attachments."
    },
    "Phishing": {
        "action": "quarantine",
        "notify_user": True,
        "quarantine": True,
        "block_sender": True,
        "create_ticket": True,
        "extract_iocs": True,
        "notify_security_team": True
    },
    "BEC": {
        "action": "quarantine",
        "notify_user": True,
        "quarantine": True,
        "block_sender": True,
        "create_ticket": True,
        "escalate_to_ir": True,
        "notify_executives": True,
        "preserve_evidence": True
    },
    "Malware_Delivery": {
        "action": "quarantine",
        "notify_user": True,
        "quarantine": True,
        "block_sender": True,
        "sandbox_attachments": True,
        "block_iocs_at_perimeter": True,
        "scan_recipient_endpoint": True,
        "create_ticket": True
    }
}
```

### IOC Extraction
```python
def extract_iocs(email_data):
    iocs = {
        "ips": [email_data["origin_ip"]],
        "domains": [email_data["sender_domain"]],
        "urls": email_data["extracted_urls"],
        "file_hashes": [att["hash_sha256"] for att in email_data["attachments"]],
        "email_addresses": [email_data["envelope_from"], email_data["reply_to"]]
    }
    
    # Remove duplicates and None values
    for key in iocs:
        iocs[key] = list(set(filter(None, iocs[key])))
    
    return iocs
```

### Output Variables
* `recommended_action` - Primary action to take
* `action_details` - Object with specific action flags
* `ioc_list` - Extracted indicators of compromise
* `notification_targets` - List of users/teams to notify

---

## Integration Notes

### SIEM/SOAR Integration
Each module outputs structured data that can be consumed by automation platforms:
```json
{
  "module_name": "authentication_evaluation",
  "timestamp": "2026-01-14T15:30:00Z",
  "inputs": {...},
  "outputs": {
    "spf_result": "pass",
    "dkim_result": "pass",
    "dmarc_result": "pass",
    "authentication_score": 90
  },
  "flags": [],
  "next_module": "origin_attribution"
}
```

### Error Handling
All modules should implement:
* Graceful degradation when data is missing
* Logging of parsing errors
* Default "unknown" values when unable to determine

### Performance Considerations
* Cache threat intel lookups (TTL: 1 hour)
* Batch process multiple emails when possible
* Implement timeout limits for external API calls (5 seconds max)

---

## Appendix: Regular Expressions

### Email Address Extraction
```regex
[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
```

### IPv4 Address
```regex
\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b
```

### IPv6 Address
```regex
(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})
```

### URL Extraction
```regex
https?://[^\s<>"]+|www\.[^\s<>"]+
```

---

**Document Version:** 1.0  
**Last Updated:** 2026-03-8 
**Maintained By:** SOC Team
