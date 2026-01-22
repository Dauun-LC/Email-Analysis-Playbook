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
