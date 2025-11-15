# Splunk SPL Queries – Frothly Cloud Compromise Investigation  
**Dataset:** `botsv3` | **Tool:** Splunk | **Analyst:** Esosa Okonedo   
**Date:** August 13, 2025 | **Duration:** ~2h 23m  

---

## Q1: List IAM Users Accessing AWS Services

**Goal:** Identify all IAM users (successful or failed) interacting with AWS.

```spl
index=botsv3 sourcetype=aws:cloudtrail 
| stats count by userIdentity.userName 
```
**Result:** splunk_access, web_admin, bstoll, btun


---

## Q2: What Processor is Used on the Web Servers?

**Goal:** Identify CPU model on hosts running Apache web servers.

```spl
index=botsv3 'Intel' OR 'AMD' sourcetype=hardware
```
```spl
index=botsv3 'Intel' OR 'AMD' sourcetype=osquery:results
```
**Result:** Intel(R) Xeon(R) CPU E5-2676


---

## Q3: Event ID of API Call That Made S3 Bucket Public

**Goal:** Find the PutBucketAcl event granting public access

```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl (userIdentity.userName=bstoll OR btun OR splunk_access OR web_admin)
| stats count by userIdentity.userName, eventName
```
```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl userIdentity.userName=bstoll
```

**Result:** ab45689d-6ccd-41e7-8705-5350402cf7ac at 1:01:46 PM


---

## Q4: Name of the S3 Bucket Made Publicly Accessible
**Goal:** Extract bucket name from the malicious PutBucketAcl event.

```spl
index=botsv3 sourcetype=aws:cloudtrail 
    eventID=ab45689d-6ccd-41e7-8705-5350402cf7ac 
| table requestParameters.bucketName
```

**Result:** frothlywebcode

---

## Q5: Name of Text File Uploaded During the time bucket was made publicly accessible
**Goal:** Find .txt file uploaded between 1:01:46 PM and 1:57:54 PM.

```spl
index=botsv3 sourcetype=aws:s3:accesslogs frothlywebcode "PUT" "*.txt*"
```

 **Result:** open_bucket_please_fix.txt at 1:02:44 PM

 ---

 ## Q6: Size (in MB) of .tar.gz File Uploaded
**Goal:** Identify .tar.gz upload and calculate size in MB.

```spl
index=botsv3 latest="08/20/2018:13:56:00" sourcetype=aws:s3:accesslogs frothlywebcode "PUT" "tar.gz"
```
```spl
index=botsv3 latest="08/20/2018:13:56:00" sourcetype=aws:s3:accesslogs frothlywebcode "PUT" "tar.gz"
| eval size_mb = round(bytes_sent / 1024 / 1024, 2)
| table _time, key, size_mb
```
**Result:** frothly.html_memcached.tar.gz → 2.93 MB

---

## Q7: Short Hostname of Endpoint Mining Monero
**Goal:** Detect Coinhive DNS activity and isolate mining host.

```spl
index=botsv3 "coinhive" 
| stats count by host
```
```spl
index=botsv3 sourcetype=stream:dns "coinhive" 
| stats count by host
| sort -count
```
```spl
index=botsv3 sourcetype=stream:dns host="mkraeus-l"
```
```spl
index=botsv3 sourcetype=stream:dns host="BSTOLL-L" "coinhive"
| timechart count span=1m
```
**Result:** BSTOLL-L → 21 DNS queries (3 @ 13:37, 14 @ 13:38, 4 @ 13:39)

---

## Q8: FQDN of Endpoint with Unique Windows OS Edition
**Goal:** Find host running different OS than others (Enterprise vs Pro).

```spl
index=botsv3 sourcetype=WinHostMon 
| stats count by ComputerName, OS
```
```spl
index=botsv3 host=BSTOLL-L sourcetype=WinEventLog:system
```

 **Result:** BSTOLL-L.FROTH.LY

---
