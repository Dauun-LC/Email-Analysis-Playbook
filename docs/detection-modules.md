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
