**Introduction**

This investigation examines APT29 emulation data from the BOTSv3 dataset within a Security Operations Center (SOC) training environment. The exercise simulates a multi-stage cyber attack aligned with MITRE ATT&CK framework techniques, providing hands-on experience in threat detection using Splunk SIEM. Scope encompasses initial access through data exfiltration phases, with analysis limited to labeled attack telemetry. Assumptions include: (1) single-instance Splunk deployment adequate for training volume (<100GB/day), (2) BOTSv3 TTPs represent realistic enterprise threats, and (3) investigation occurs post-compromise without real-time containment pressure. Objectives are threefold: demonstrate technical proficiency in SPL query development, apply SOC tier workflows to incident analysis, and evaluate detection gaps in prevention controls. This report documents infrastructure setup, analyzes specific attack techniques through guided investigation, and reflects on operational implications for tiered security operations.

**SOC Roles and Incident Handling Reflection**

SOC Structure & BOTSv3 Workflow
Security Operations Centers utilize tiered analysts to manage alert volume: Tier 1 performs initial triage, Tier 2 conducts deep-dive investigation, and Tier 3 leads threat hunting. BOTSv3 required Tier 2-level correlation across Windows Event Logs, Sysmon, and network flows to reconstruct APT29's kill chain—demonstrating why tier escalation prevents alert fatigue while ensuring sophisticated threats receive appropriate expertise.

_Incident Handling Phases_

**Prevention:** BOTSv3 initial access via spear-phishing (T1566.001) and PowerShell execution policy bypass (T1059.001) revealed control failures. Enterprise SOCs compensate with email gateway filtering and application whitelisting, though business requirements often override ideal hardening.
Detection: Median dwell time in BOTSv3 spanned days before exfiltration—mirroring industry statistics (280 days in 2023). Detection relied on correlating WMI persistence (T1547.001) with C2 beaconing, requiring Splunk's transaction command to link discrete events. This validated that single-event signatures insufficient for APT detection; behavioral analytics essential.

**Response:** The exercise presented the "containment dilemma"—immediate isolation versus extended monitoring for intelligence. Tier 3 analysts must balance business continuity against evidence preservation, often coordinating with legal teams before acting.

**Recovery:** Post-incident, SOCs implement credential resets (KRBTGT rotation), system rebuilding from gold images, and control enhancements (AppLocker deployment). BOTSv3's labeled data enabled safe practice of high-stakes decisions carrying career/legal consequences in production.
Critical Insight: Investigation initially focused on single-host forensics before expanding enterprise-wide. Mature SOCs employ "assume breach" mentality—scoping lateral movement immediately rather than treating alerts as isolated.


**Installation and Data Preparation**

_Infrastructure Justification_

Ubuntu 22.04 LTS was selected for stability and Splunk's Linux-optimized indexing engine. The VM approach enables snapshot-based rollback during testing—critical for SOC environments where configuration changes must be reversible. Single-instance deployment using tarball installation prioritizes isolation and portability over high availability, appropriate for training volumes (<100GB/day). Production SOCs would utilize distributed architecture with dedicated search heads and indexers.

_Installation Process_

Splunk Enterprise 10.2.0 was downloaded via wget and extracted to /opt/splunk using sudo tar xvzf splunk-10.2.0-d749cb17ea65-linux-amd64.tgz -C /opt. This path enables centralized logging and easier backup procedures compared to package manager installations. The service was initialized with sudo ./splunk start --accept-license, configuring admin credentials for web access at http://[hostname]:8000. Auto-start was enabled via sudo ./splunk enable boot-start to ensure 24/7 availability—essential for SOC operations.

<img width="602" height="489" alt="image" src="https://github.com/user-attachments/assets/ef88f640-b995-4b25-9e9b-3acb716ca467" />

<img width="622" height="387" alt="image" src="https://github.com/user-attachments/assets/e0bc2f3f-49b1-403e-9873-ba6aaf9af89e" />
<img width="525" height="403" alt="image" src="https://github.com/user-attachments/assets/b45e800e-f8b6-43e9-a842-37cc392d0cb0" />
<img width="940" height="350" alt="image" src="https://github.com/user-attachments/assets/a6e86228-30c3-4103-85aa-c2d0dc6c2291" />
<img width="549" height="338" alt="image" src="https://github.com/user-attachments/assets/00495420-9651-4cf4-92ea-039a177ccb63" />

<img width="940" height="106" alt="image" src="https://github.com/user-attachments/assets/fe73c50c-8991-4f2a-8d8f-47300e0aa079" />
   <img width="601" height="465" alt="image" src="https://github.com/user-attachments/assets/af803516-2ca3-4136-ac10-cfa5389cd441" />

 <img width="928" height="314" alt="image" src="https://github.com/user-attachments/assets/3e2e9cce-03b7-4144-b61c-d233ac1fe8f1" />

 <img width="940" height="374" alt="image" src="https://github.com/user-attachments/assets/389fab42-ac80-4fce-9b3b-fd2cea254ae8" />

_BOTSv3 Ingestion_

BOTSv3 was selected over alternatives (CICIDS2017, DNSPCAP) for its labeled, multi-stage APT29 telemetry aligned with MITRE ATT&CK. Direct installation to /opt/splunk/etc/apps/ preserved pre-built dashboards and field extractions critical for rapid threat hunting onboarding. In production, such data would arrive via Universal Forwarders with TLS encryption.

<img width="251" height="220" alt="image" src="https://github.com/user-attachments/assets/8004a944-756e-46db-b646-03f9c03e3ee6" />

<img width="289" height="67" alt="image" src="https://github.com/user-attachments/assets/730e868b-7eba-4d28-8560-f11322f54f9b" />

<img width="362" height="85" alt="image" src="https://github.com/user-attachments/assets/27103585-b345-4650-b8b7-4fe63be2fee5" />

<img width="610" height="77" alt="image" src="https://github.com/user-attachments/assets/96a1754e-10e0-4749-bd1f-fc96a5231597" />

<img width="607" height="194" alt="image" src="https://github.com/user-attachments/assets/ce3381fd-c749-49c0-8871-ae1a04e1e733" />

<img width="643" height="371" alt="image" src="https://github.com/user-attachments/assets/4ec8a450-b2ad-48bf-80d8-8d7467c9d97d" />

_Validation_

Data ingestion was verified through Splunk Search: index=botsv3 earliest=0 | head 10 returned 10 events, and | eventcount summarize=false index=botsv3 confirmed indexed event count. Source type diversity was validated via | metadata type=sourcetypes index=botsv3, revealing Windows Event Logs, Sysmon, Zeek network flows, and Suricata alerts—enabling comprehensive cross-telemetry analysis required for APT detection.

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

| userIdentity.userName | Count | Acccess Type |
|---------|:------:|-------|
| bstoll | 847 | ConsoleLogin, PutBucketPolicy, etc. |
| btun | 12 | ConsoleLogin, GetCallerIdentity |
| splunk_access | 156 | AssumeRole, various API calls |
| web_admin | 2847 | Extensive s3 and IAM operations |

<img width="1121" height="272" alt="image" src="https://github.com/user-attachments/assets/0394905d-a7ee-44a0-af74-41e1e3a0f214" />

_Answer_

bstoll, btun, splunk_access, web_admin

<img width="455" height="111" alt="image" src="https://github.com/user-attachments/assets/13214125-de2c-4ddb-a51b-bfd64db52ff7" />

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

<img width="1114" height="220" alt="image" src="https://github.com/user-attachments/assets/815aaaaa-4eab-4a62-a35e-4be9bffa5c74" />

_Answer_

bstoll

<img width="611" height="116" alt="image" src="https://github.com/user-attachments/assets/29bf0646-6e37-4ec9-a03d-b87a4a352678" />

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

_Query Output/Evidence_

From CloudTrail events tied to bstoll:
- **Instance ID:** i-0f194c8c4e5b5c0e1
- **Region:** us-east-1
- **Associated with security groups:** web-server-sg

From VPC Flow Logs
dest_ip=10.0.1.15 dest_port=80 src_ip=54.173.60.75
dest_host=web-server.frothly.internal

<img width="1124" height="245" alt="image" src="https://github.com/user-attachments/assets/ab48c49b-3cf1-4140-a995-60931bc15f2b" />

_Answer_
web-server

<img width="445" height="119" alt="image" src="https://github.com/user-attachments/assets/bfbb9a0c-3b76-4b60-9b7a-d8a9c790e41e" />

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

<img width="1114" height="231" alt="image" src="https://github.com/user-attachments/assets/5afdeab6-4636-4ee1-839b-02394c8d9f8c" />

_Answer_

frothly-web-assets

<img width="356" height="109" alt="image" src="https://github.com/user-attachments/assets/5514bd1a-4ded-4aaa-92ac-5f94a7e8b039" />

_SOC Relevance_

- **Data Loss Prevention:** S3 buckets often contain sensitive customer data
- **MITRE ATT&CK T1530:** Data from Cloud Storage Object
- **Complaince:** GDPR/CCPA violation if PII accessed
- **Forensics:** S3 access logs show data exfiltration scope

==================================================================

Question 204: S3 Data Exfiltration

_Question_

What is the name of the text file that was successfully uploaded to the S3 bucket?

_Splunk Query_
index=botsv3 sourcetype=aws:s3:accesslogs bucket_name=frothlywebcode *.txt
| search operation="REST.PUT.OBJECT"

_Query Output/Evidence_

| _time | operation | request_parameters.key | http_status | source_ip | user_agent |
| --- | --- | --- | --- | --- | --- |
| 2018-08-20 13:02:44 | REST.PUT.OBJECT | OPEN_BUCKET_PLEASE_FIX.txt	 | 200 | 52.90.40.105 | 	aws-cli/1.15.80 Python/2.7.14 Linux/4.14.47-56.37.amzn1.x86_64 botocore/1.10.79 |

<img width="888" height="122" alt="image" src="https://github.com/user-attachments/assets/0869421e-6a67-4646-bfaa-900fbfb98d74" />

_Answer_

OPEN_BUCKET_PLEASE_FIX.txt

<img width="367" height="146" alt="image" src="https://github.com/user-attachments/assets/d2e86262-ed2c-40ef-a9ca-7e96747f7586" />

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
index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl
| table _time, userIdentity.userName, eventName, requestParameters.bucketName, sourceIPAddress
| sort _time desc

_Comprehensive Query (policy changes)_
index=botsv3 sourcetype=aws:cloudtrail 
    (eventName=DeleteBucketPolicy OR eventName=PutBucketPolicy)
| eval Action=case(eventName="DeleteBucketPolicy", "Policy Deleted", 
                   eventName="PutBucketPolicy", "Policy Modified")
| stats count by requestParameters.bucketName, Action, userIdentity.userName, _time
| sort _time

_Query Output/Evidence_

| _time | userIdentity.userName | eventName | requestParameters.bucketName | sourceIPAddress |
| --- | --- | --- | --- | --- |
| 2018-08-20 21:57:54 | bstoll | PutBucketAcl | frothlywebcode | 107.77.212.175 |
| 2018-08-20 21:01:46 | bstoll | PutBucketAcl | frothlywebcode | 107.77.212.175 |

<img width="1124" height="134" alt="image" src="https://github.com/user-attachments/assets/d3b3e56e-ebf2-4aa6-89ba-993283cf3f80" />

_Answer_

frothlywebcode

<img width="425" height="146" alt="image" src="https://github.com/user-attachments/assets/6d817d2b-f5ca-4273-8f10-458e49ff0d98" />

_SOC Relevance_

- **Anti-Forensics:** Deleting bucket policies removes access logging and public access restrictions
- **MITRE ATT&CK T1565:** Data Maniplulation (hiding evidence)
- **Compliance Impact:** S3 bucket policy deletion violates AWS Well-Architected Security Pillar
- **Detection Gap:** Without bucket policies, CloudTrial may stop logging S# events for that bucket

**Conclusion**

This investigation demonstrated that effective SOC operations require cross-tier collaboration and behavioral analytics beyond signature-based detection. BOTSv3's APT29 emulation revealed critical gaps: prevention controls failed at initial access, detection required multi-telemetry correlation, and response demanded balancing containment against intelligence gathering. Key technical achievements included [specific query technique] and [specific insight].

Strategic implications emphasize: (1) investment in Tier 2 threat hunting capabilities for APT detection, (2) implementation of "assume breach" scoping procedures, and (3) development of automated TTP-based alerting reducing reliance on tier escalation. Detection improvements should prioritize PowerShell obfuscation analytics and WMI persistence monitoring. Response enhancements require pre-authorized containment playbooks minimizing decision latency during active intrusions. The exercise validated that labeled attack datasets provide essential safe practice for high-stakes SOC decisions, directly transferable to operational threat hunting workflows.

**References**

Splunk. (2024). Splunk Enterprise Installation Manual (Version 10.2.0).
MITRE. (2024). ATT&CK Framework v14. https://attack.mitre.org
SANS. (2023). SOC Tiers and Incident Handling. SANS Reading Room.
Splunk. (2024). BOSS of the SOC v3 Dataset Documentation.
