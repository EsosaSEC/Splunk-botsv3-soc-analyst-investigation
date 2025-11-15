# Tier 1 SOC Analyst Project: Frothly Cloud Compromise Investigation
 

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?logo=splunk&logoColor=green)
![AWS](https://img.shields.io/badge/Cloud-AWS-F90?logo=amazonaws)
![NIST](https://img.shields.io/badge/Standard-NIST%20800--61r2-blue)

**Author:** Esosa Okonedo  
**X Handle:** [@FineBoyJermaine](https://twitter.com/J_e_r_m_a_i_n_e)  
**Completed:** August 13, 2025  
**Dataset:** Splunk BOTSv3 (Hybrid Cloud)  
**Duration:** ~2h 23m  

---

## Project Overview

Simulated a **Tier 1 SOC Analyst** role using **Splunk** to investigate a breach in the **Frothly** cloud environment.

**Goals:**  
- Detect S3 misconfigurations  
- Identify unauthorized uploads  
- Detect cryptomining on endpoints  
- Correlate AWS, DNS, Sysmon, and Windows logs  
- Deliver a **NIST 800-61r2** incident report  

**Outcome:**  
- Accidental public S3 exposure → malicious uploads → **Monero cryptomining** on `BSTOLL-L.FROTH.LY`

---

## Key Findings

| Objective | Result |
|---------|--------|
| IAM users accessing AWS | `splunk_access`, `web_admin`, `bstoll`, `btun` |
| Web server CPU | `Intel(R) Xeon(R) CPU E5-2676` |
| Event ID (public S3) | `ab45689d-6ccd-41e7-8705-5350402cf7ac` |
| Exposed S3 bucket | `frothlywebcode` |
| Uploaded text file | `open_bucket_please_fix.txt` |
| Malicious .tar.gz size | **2.93 MB** |
| Mining host (short) | `BSTOLL` |
| Mining host (FQDN) | `BSTOLL-L.FROTH.LY` (Windows 10 **Enterprise**) |

---
---

## Skills Demonstrated

- **Splunk SPL** (CloudTrail, S3 Access Logs, `stream:dns`, `WinHostMon`)
- **Log correlation** across 5+ sources
- **Threat hunting** (Coinhive DNS, PutBucketAcl)
- **MITRE ATT&CK** mapping
- **NIST 800-61r2** incident lifecycle
- **Cloud security** (IAM, S3 ACLs, public bucket risks)
- **Cryptomining detection**

---

## Attack Chain (MITRE ATT&CK)

| Phase | Tactic | Technique |
|-------|--------|-----------|
| Initial Access | [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage |
| Execution | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Malicious File |
| Impact | [T1496](https://attack.mitre.org/techniques/T1496/) | **Resource Hijacking (Monero)** |
| Command & Control | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS (coinhive.com) |

---

## SPL Query Highlights

```spl
# Q1: IAM Users
index=botsv3 sourcetype=aws:cloudtrail 
| stats count by userIdentity.userName

# Q3: Public Bucket Event ID
```index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl userIdentity.userName=bstoll 
| table _time, eventID, requestParameters

# Q7: Cryptomining DNS (Coinhive)
index=botsv3 sourcetype=stream:dns "coinhive" 
| timechart span=1m count by query
```

> Full queries → [`splunk-queries/queries.md`](https://github.com/EsosaSEC/Splunk-botsv3-soc-analyst-investigation/blob/main/Splunk-Queries/queries.md)

---

## Incident Summary

IAM user **`bstoll`** accidentally made S3 bucket `frothlywebcode` public via `PutBucketAcl` (Event ID: `ab45689d-...`).  
Within **56 minutes**, attackers uploaded:  
- `open_bucket_please_fix.txt` (taunt)  
- `frothly.html_memcached.tar.gz` (**2.93 MB**)  

The payload likely executed on **`BSTOLL-L.FROTH.LY`**, triggering **21 DNS queries** to `coinhive.com` → **Monero mining**.

Bucket was re-secured at **1:57 PM**. Mining continued until isolated.

---

## Recommendations

1. **Enable AWS S3 Block Public Access** (org-wide)  
2. **Enforce IAM least privilege** + MFA for `bstoll`  
3. **Deploy EDR** on all endpoints (priority: Windows 10 Enterprise)  
4. **Splunk Alerts**:  
   - `PutBucketAcl` + `AllUsers`  
   - DNS to `coinhive.com`, `*.stratum`, `xmr.*`  
5. **Reimage** `BSTOLL-L.FROTH.LY` from clean backup  
6. **User training** on S3 ACLs

---

## Full Report

[Download PDF](https://docs.google.com/document/d/1NgtzkfschPFR3gEam1qHGMNjimBiTlLV6dG5rclENho/edit?usp=drive_link)  


---

## About Me

**Esosa Okonedo** – Entry-Level SOC Analyst | Splunk | AWS | Blue Team  
- [X (Twitter)](https://twitter.com/FineBoyJermaine)  
- [LinkedIn](https://linkedin.com/in/esosaokonedo) *(update link)*  
- [TryHackMe](https://tryhackme.com/p/FineBoyJermaine) *(if applicable)*  
- **Certifications:** Google Cybersecurity Professional, Splunk Fundamentals 1  

> *Based on Splunk’s public BOTSv3 dataset: [github.com/splunk/botsv3](https://github.com/splunk/botsv3)*

