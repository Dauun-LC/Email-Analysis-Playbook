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
