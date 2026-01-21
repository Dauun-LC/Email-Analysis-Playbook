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
