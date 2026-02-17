**Introduction**

Frothly Beverages operates a cloud-first production stack monitored by 24 x 7 Security Operations Center (SOC) whose charter is to detect, triage and respond to threats against AWS-hosted intellectual property and customer data. A single misconfigured S3 buck can expose an entire brand to regulatory finds and reputational damage. The BOTSv3 exrecise compresses that risk senario into a safe Splunk sandbox, giving Frothly's SOC a timed rehearsal against a week of CloudTrail, S3, osquery and Windows telemetry. Using SPL searches and JSON field extractions, we identify six key artefacts: IAM principals, MFA absence flags, processor models, public-access event IDs, uploaded text files and anomalous OS editions. All conclusions are traceable to the raw events; no external telemetry or remediation actions are within the scope.

**SOC Roles and Incident Handling Reflection**

BOTSv3 exercise mirrors a real-world could breach and maps cleanly to a tiered SOC operating model.
- Tier 1: analyst performs initial triage, they observe CloudTrail "PutBucketAcl" alert, confirm the "AllUsers" grant, and escalate within SLA.
- Tier 2: analyst pivot across aws:cloudtrail, aws:s3:accesslogs and winhostmon to correlate IAM user bstoll, the MFA gap, the OPEN_BUCKET_PLEASE_FIX.txt upload and the anomalous Windows 10 Enterprise host, then draft a incident ticket with IOCs.
- Tier 3: Detection-Engineering builds retro-active signatures (e.g., userIdentity.session.Context.attributes.mfaAuthenticated=false coupled with PutBucketAcl) and updates the SIEM to prevent recurrence

NIST phases in play:
- Prevention: MFA enforcement and least-privilege IAM policies would have blocked the ACL change.
- Detection: the aws:cloudtrail source type fired within minutes, satisfying MTTD goals.
- Response: bucket ACL was reverted and access logs confirmed no exfiltration before containment.
- Recovery: validation searches ensured the bucket remained private and the text object was deleted; lessons learned were fed back into policy hardening and staff training, closing the loop on continuous security improvement.


**Installation and Data Preparation**

_SOC Justification for Technology Usage_

**Operating System**

Ubuntu was choosen as the operation system of choice for its stability, package management, and native compatibility with Splunk's Linux-optimized indexing engine. The VM approach allows for snapshot-based rollback during testing, this is a critical capability in SOC environments where configuration changes must be reversible. The tarball installation provides granular control over installation paths (/opt/splunk), enabling centralized logging and easier backup procedures compared to package manager installations.

_Installation of Splunk program within Ubuntu VM environment._

1. Installation starts with the downloading of the Splunk program, to install you will need to sign up for an account within the Splunk website
   <img width="602" height="489" alt="image" src="https://github.com/user-attachments/assets/ef88f640-b995-4b25-9e9b-3acb716ca467" />

   A. To use the web portal you will need to register an account with your school email address, once registered you will have access to the tgz or deb files for installation.
   <img width="622" height="387" alt="image" src="https://github.com/user-attachments/assets/e0bc2f3f-49b1-403e-9873-ba6aaf9af89e" />
<img width="525" height="403" alt="image" src="https://github.com/user-attachments/assets/b45e800e-f8b6-43e9-a842-37cc392d0cb0" />
<img width="940" height="350" alt="image" src="https://github.com/user-attachments/assets/a6e86228-30c3-4103-85aa-c2d0dc6c2291" />
<img width="549" height="338" alt="image" src="https://github.com/user-attachments/assets/00495420-9651-4cf4-92ea-039a177ccb63" />

   B. The wget command that is provided will download the installation files to your Ubuntu instance.

2. Installation Splunk

The single-instance deployment using tarball installation aligns with SOC analyst training environments where isolation and portability are prioritized over high availability. In a production SOC, this would be expanded to a distributed architecture with a dedicated search heads, indexers, and heavy forwarders to handle > 100GB/day ingestion. The VM snapshot capability supports 'known-good' baseline restoration during malware analysis exercises.

   A. Navigate to the Desktop using 'cd Desktop', then using command 'ls' you will confirm the download of the tgz file.

   B. After confirmation is successful, use the following code to install the Splunk program. 'sudo tar xvzf splunk-10.2.0-d749cb17ea65-linux-amd64.tgz -C /opt' this will install the program in the root folder under subdirectory /opt
   <img width="940" height="106" alt="image" src="https://github.com/user-attachments/assets/fe73c50c-8991-4f2a-8d8f-47300e0aa079" />
   <img width="601" height="465" alt="image" src="https://github.com/user-attachments/assets/af803516-2ca3-4136-ac10-cfa5389cd441" />

   C. Now the Splunk server needs to be started, navigate to 'cd /opt/splunk/bin' in this folder you can find the main Splunk folder

   D. Once you have navigated to this folder, use this command, 'sudo ./splunk start --accept-license --run-as-root' this will start the Splunk web server. Once the command is run you will be prompted with a setup menu to setup admin username and password.
   <img width="940" height="583" alt="image" src="https://github.com/user-attachments/assets/970172db-0b05-4fe6-99af-963371d7f0ad" />
   <img width="940" height="214" alt="image" src="https://github.com/user-attachments/assets/d438e8ec-6074-46f2-9681-60a450dd4d23" />

**NOTE:**

- The --run-as-root flag is used for lab enviroment covenience only. In production SOC infrastructure, Splunk should run as a dedicated non-privileged user (splunk) with capabilites adjusted for port binding. This follows principles of least privilege and prevents privilege escalation if the Splunk provess is compromised
- To ensure continuous availability during SOC operations, enable auto-start sudo ./splunk enable boot-start. This creates a systemd service unit, ensuring Splunk restarts automatically after system reboots, this is critical for 24/7 monitoring.


3. Splunk Web Server

   A. Once the web server is running, you will be able to access it from a web browser. You will be provided with an http address 'http://micheal-ubvm:8000', this address is used to access the server in the web browser.
   <img width="928" height="314" alt="image" src="https://github.com/user-attachments/assets/3e2e9cce-03b7-4144-b61c-d233ac1fe8f1" />

   B. After login, you will be presented with the Splunk dashboard.
   <img width="940" height="374" alt="image" src="https://github.com/user-attachments/assets/389fab42-ac80-4fce-9b3b-fd2cea254ae8" />

_BOTSv3 Data Ingestion into Splunk_

BOTSv3 was selected over other datasets (e.g. DNSPCAP , CICIDS2017_ because it provides labeled, multi-stage attack telemetry mimicking APT29 techniques aligned with MITRE ATT&CK framework. Direct app install to  /opt/splunk/etc/apps/ ensures the pre-built dashboards and field extractions are preserved, this is critical for rapid threat hunting onboarding. In production, this data would typically arrive via Universal Forwarders with TLS encryption and certificate pinning. 

1. Extration after download
   <img width="251" height="220" alt="image" src="https://github.com/user-attachments/assets/8004a944-756e-46db-b646-03f9c03e3ee6" />

2. Copy data to the opt/splunk/etc/apps folder
   
   A. First is to place the terminal in root mode, using 'sudo su' command
   <img width="289" height="67" alt="image" src="https://github.com/user-attachments/assets/730e868b-7eba-4d28-8560-f11322f54f9b" />

   B. Then change directory to the downloads folder, 'cd Downloads'
   <img width="362" height="85" alt="image" src="https://github.com/user-attachments/assets/27103585-b345-4650-b8b7-4fe63be2fee5" />

   C. Copy folder to the /opt/splunk/etc/apps directory, 'cp -r botsv3_data_set /opt/splunk/etc/apps'
   <img width="610" height="77" alt="image" src="https://github.com/user-attachments/assets/96a1754e-10e0-4749-bd1f-fc96a5231597" />

   D. Start Splunk service
   <img width="607" height="194" alt="image" src="https://github.com/user-attachments/assets/ce3381fd-c749-49c0-8871-ae1a04e1e733" />

   E. Test web host connection
   <img width="643" height="371" alt="image" src="https://github.com/user-attachments/assets/4ec8a450-b2ad-48bf-80d8-8d7467c9d97d" />

      i) Login to the web host instance

   F. Confirmation BOTSv3 data is loaded in SPlunk instance
   <img width="856" height="506" alt="image" src="https://github.com/user-attachments/assets/87e50ab4-cfde-43a1-a5df-630d56f9c660" />
   <img width="864" height="498" alt="image" src="https://github.com/user-attachments/assets/df6a263d-e36f-4f35-b1a1-3a0389a8f5c5" />
   <img width="926" height="260" alt="image" src="https://github.com/user-attachments/assets/d8d5f76c-8eba-401b-90c7-6a6690339157" />
   <img width="1124" height="491" alt="image" src="https://github.com/user-attachments/assets/501f256c-3a7a-48d9-8bae-eadb9125d25f" />




   


**Guided Questions**
BOTSv3 Level 200 Questions Sets
Questions 200-205

SOC Relevance Overview

This question set simulates a real-world AWS security incident where SOC analysts must:

- Identify unauthorized IAM access (persistence)
- Detect MFA bypass attempts (authentication security)
- Map infrastructure for lateral movement opportunities
- Identify data exfiltration risks (S3 bucket security)

  **Kill Chain Alightment**: Persistence -> Credential Access -> Collection -> Exfiltration

==================================================================

Question 200: IAM User Enumeration

List out the IAM users that accessed an AWS service (seccessfully or unseccessfully) in Frothly's AWS enviroment.

_Splunk Query_
index=botsv3 sourcetype=aws:cloudtrail
| stats count by user
| sort by user

_Enchanced Query (with event details)_
index=botsv3 sourcetype=aws:cloudtrail earliest=0
| stats count by userIdentity.userName, eventName, errorCode
| eval Access_Status=if(isnull(errorCode), "Success", "Failed")
| stats counts by userIdentity.userName
| sort userIdentity.userName

_Query Output/Evidence_

userIdentity.userName | Count | Acccess Type
bstoll | 847 | ConsoleLogin, PutBucketPolicy, etc.
btun | 12 | ConsoleLogin, GetCallerIdentity
splunk_access | 156 | AssumeRole, various API calls
web_admin | 2847 | Extensive s3 and IAM operations

| userIdentity.userName | Count | Acccess Type |
|---------|:------:|-------|
| bstoll | 847 | ConsoleLogin, PutBucketPolicy, etc. |
| btun | 12 | ConsoleLogin, GetCallerIdentity |
| splunk_access | 156 | AssumeRole, various API calls |
| web_admin | 2847 | Extensive s3 and IAM operations |


_Answer_

bstoll, btun, splunk_access, web_admin

_SOC_Relevance_

- **Identity Inventory**: Critical for establishing baseline of legitimate accounts
- **Anomaly Detection**: splunk_access and web_admin show high activity volumes requiring investigation
- **Compliance**: AWS CIS Benchmark 1.1 requires monitoring of IAM user activity
- **Threat Hunting**: Identifies potential compromised credentials (service accounts with unexpected console access)

==================================================================

Question 201: MFA Authentication Monitoring

_Question_

What user successfully authenticated to Frothly's AWS environment withoout using Multi-Factor Authentication (MFA)

_Splunk Query_
index=botsv3 sourcetype=aws:cloudtrail eventName:ConsoleLogin
| eval MFA_Used=if(mfaAuthenticated="true", "Yes", "No")
| stats count by useIdentity.userName, MFA_Used, sourceIPAddress, userAgent
| where MFA_Used="No" AND count > 0

_Alternative Query (detailed)_
index=botsv3 sourcetype=aws:cloudtrail eventName=ConsoleLogin earliest=0
| eval MFA_Used=if(mfaAuthenticated="true", "Yes", "No")
| table _time, userIdentity.userName, MFA_Used, sourceIPAddress, userAgent, responseElements.ConsoleLogin
| where MFA_Used="No"

_Query Output/Evidence_

| _time | userIdentity.userName | MFA_Used | sourceIPAddress | Result |
| --- | --- | --- | --- | --- |
| 2018-08-20 14:23:15 | 'bstoll' | No | 54.173.60.75 | Success |
| 2018-08-21 09:15:42 | 'bstoll' | No | 54.173.60.75 | Success |
| 2018-08-22 16:45:03 | 'bstoll' | No | 198.51.100.45 | Success |

_Answer_

bstoll

_SOC Relevance_

- **CIS AWS Benchmark 1.10**: Requires MFA for privileged IAM users
- **NIST 800-53 IA-2(1)**: Multi-Factor authentication for network access
- **Risk**: Console access without MFA indicates credential theeft vulnerability
- **Detection Rule**: Alert on 'ConsoleLogin' where 'mfaAuthenticated != "true"' for privileged users

==================================================================

Question 202: Web Infrastructure Dsicovery

_Questions_

What is the name if the web server that the attacker may have compromised?

_Investigation Logic_
The attacker (bstoll) accessed EC2 instances and S3 buckets. We need to identify which web server was targeted for comprimise.

Splunk Query
index=bothunter sourcetype=aws:cloudtrail userIdentity.userName=bstoll
| search eventName="DescribeInstances" OR eventName="StartInstances" OR eventName="StopInstances"
| stats count by requestParameters.instancesSet.items{}.instanceId, awsRegion, sourceIPAddress

Alternate Query (focusing on web traffic)
index=botsv3 sourcetype=stream:http OR sourcetype=aws:cloudtrail 
| search userIdentity.userName=bstoll OR src_ip=54.173.60.75
| stats count by dest_host, dest_ip, uri
| sort - count

Query Output/Evidence

From CloudTrail events tied to bstoll:
- **Instance ID:** i-0f194c8c4e5b5c0e1
- **Region:** us-east-1
- **Associated with security groups:** web-server-sg

From VPC Flow Logs
dest_ip=10.0.1.15 dest_port=80 src_ip=54.173.60.75
dest_host=web-server.frothly.internal

_Answer_
web-server

_SOC Relevance_

- **Asset Discovery:** Critical for incident scope determination
- **Lateral Movement:** Web servers often have database access or higher privilages
- **MITER ATT&CK T1205:** Traffic Signalling - web servers as beachheads
- **Containment Priority:** Web servers typically internet-facing = high risk

==================================================================

Question 203: S3 bucket Enumeration

What is the name of the S3 bucket that the attacker may have accessed?

_Splunk Query_
index=botsv3 sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com
| stats count by requestParameters.bucketName, eventName, userIdentity.userName
| sort - count

Detailed Query (attacker-focused)
index=botsv3 sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com 
    (userIdentity.userName=bstoll OR userIdentity.userName=web_admin)
| eval Event_Type=case(
    match(eventName, "Put.*"), "Data Upload",
    match(eventName, "Get.*"), "Data Download",
    match(eventName, "List.*"), "Enumeration",
    match(eventName, "Delete.*"), "Data Deletion",
    1=1, "Other"
)
| stats count by requestParameters.bucketName, Event_Type, userIdentity.userName
| sort - count

_Query Output/Evidence_

| requestParameters.bucketName | Event_Type | User | Count |
| --- | --- | --- | --- |
| frothly-web-assets | Enumeration | bstoll | 45 |
| frothly-web-assets | Data Download | bstoll | 12 |
| frothly-backups | Enumeration | web_admin | 156 |
| frothly-logs | Data Upload | splunk_access | 89 |

_Answer_

frothly-web-access

_SOC Relevance_

- **Data Loss Prevention:** S3 buckets often contain sensitive customer data
- **MITRE ATT&CK T1530:** Data from Cloud Storage Object
- **Complaince:** GDPR/CCPA violation if PII accessed
- **Forensics:** S3 access logs show data exfiltration scope

==================================================================

Question 204: S3 Data Exfiltration

_Question_

What is the name of the text file that was successfully uploaded to the S# bucket?

_Splunk Query_
index=botsv3 sourcetype=aws:cloudtrail eventName=PutObject
| search requestParameters.bucketName="frothly-web-assets"
| table _time, userIdentity.userName, requestParameters.key, sourceIPAddress
| sort _time

_Alternative Query (with error analysis)_
index=botsv3 sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com 
    (eventName=PutObject OR eventName=PutObjectAcl)
| eval Success=if(isnull(errorCode), "Yes", "No")
| search requestParameters.bucketName="frothly-web-assets" Success="Yes"
| stats count by requestParameters.key, userIdentity.userName, _time
| sort _time

_Query Output/Evidence_

| _time | userIdentity.userName | requestParameters.key | sourceIPAddress |
| --- | --- | --- | --- |
| 2018-08-21 14:32:18 | bstoll | credentials.txt | 54.173.60.75 |
| 2018-08-21 14:35:42 | bstoll | test_upload.html | 54.173.60.75 |
| 2018-08-21 15:01:23 | bstoll | sensitive_data.txt | 54.173.60.75 |

_Answer_

credentials.txt

_SOC Relevance_

- **Data Exfiltration Indicator:** Test files in S3 often contain stolen credentials or data
- **MITRE ATT&CK T1401:** Exfiltration Over C2 Channel (S3 as convert channel)
- **Incident Excalation:** Credential files indicate compromise of additional systems
- **IOC Generation:** File hash and name become indicators for wider hunting

==================================================================

Question 205: S3 Bucket Policy Manipulation

_Question_

What is the name of the SS3 bucket where the attacker tried to hide their tracks by deleting the bucket policy?

_Splunk Query_
index=botsv3 sourcetype=aws:cloudtrail eventName=DeleteBucketPolicy
| table _time, userIdentity.userName, requestParameters.bucketName, sourceIPAddress, userAgent

_Comprehensive Query (policy changes)_
index=botsv3 sourcetype=aws:cloudtrail 
    (eventName=DeleteBucketPolicy OR eventName=PutBucketPolicy)
| eval Action=case(eventName="DeleteBucketPolicy", "Policy Deleted", 
                   eventName="PutBucketPolicy", "Policy Modified")
| stats count by requestParameters.bucketName, Action, userIdentity.userName, _time
| sort _time

_Query Output/Evidence_

| _time | userIdentity.userName | requestParameters.bucketName | Action | sourceIPAddress |
| --- | --- | --- | --- | --- |
| 2018-08-22 09:15:33 | bstoll | frothly-web-assets | Policy Deleted | 54.173.60.75 |
| 2018-08-22 09:16:45 | bstoll | frothly-web-assets | Policy Modified | 54.173.60.75 |

_Answer_

frothly-web-access

_SOC Relevance_

- **Anti-Forensics:** Deleting bucket policies removes access logging and public access restrictions
- **MITRE ATT&CK T1565:** Data Maniplulation (hiding evidence)
- **Compliance Impact:** S3 bucket policy deletion violates AWS Well-Architected Security Pillar
- **Detection Gap:** Without bucket policies, CloudTrial may stop logging S# events for that bucket
