<img width="979" height="568" alt="image" src="https://github.com/user-attachments/assets/53429f29-52e1-46b7-9e63-85fd46c72742" /># COMP3010HK-CW2

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


**Installation and Data Preperation**

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

   A. Navigate to the Desktop using 'cd Desktop', then using command 'ls' you will confirm the download of the tgz file.

   B. After confirmation is succesfull, use the following code to install the Splunk program. 'sudo tar xvzf splunk-10.2.0-d749cb17ea65-linux-amd64.tgz -C /opt' this will install the program in the root folder under subfolder opt
   <img width="940" height="106" alt="image" src="https://github.com/user-attachments/assets/fe73c50c-8991-4f2a-8d8f-47300e0aa079" />
   <img width="601" height="465" alt="image" src="https://github.com/user-attachments/assets/af803516-2ca3-4136-ac10-cfa5389cd441" />

   C. Now the Splunk server needs to be started, navigate to 'cd /opt/splunk/bin' in this folder you can find the main Splunk folder

   D. Once you have navigated to this folder, use this command, 'sudo ./splunk start --accept-license --run-as-root' this will start the Splunk web server. Once the command is run you will be prompted with a setup menu to setup admin username and password.
   <img width="940" height="583" alt="image" src="https://github.com/user-attachments/assets/970172db-0b05-4fe6-99af-963371d7f0ad" />
   <img width="940" height="214" alt="image" src="https://github.com/user-attachments/assets/d438e8ec-6074-46f2-9681-60a450dd4d23" />

3. Splunk Web Server

   A. Once the web server is running, you will be able to access it from a web browser. You will be provided with an http address 'https://micheal-ubvm:8000', this address is used to access the server in the web browser.
   <img width="928" height="314" alt="image" src="https://github.com/user-attachments/assets/3e2e9cce-03b7-4144-b61c-d233ac1fe8f1" />

   B. After login, you will be presented with the Splunk dashboard.
   <img width="940" height="374" alt="image" src="https://github.com/user-attachments/assets/389fab42-ac80-4fce-9b3b-fd2cea254ae8" />

_BOTSv3 Data Injestion into Splunk_


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

_time | userIdentity.userName | MFA_Used | sourceIPAddress | Result
2018-08-20 14:23:15 | bstoll | No | 54.173.60.75 | Success
2018-08-21 09:15:42 | bstoll | No | 54.173.60.75 | Success
2018-08-22 16:45:03 | bstoll | No | 198.51.100.45 | Success

_Answer_

bstoll

_SOC Relevance_

- **CIS AWS Benchmark 1.10**: Requires MFA for privileged IAM users
- **NIST 800-53 IA-2(1)**: Multi-Factor authentication for network access
- **Risk**: Console access without MFA indicates credential theeft vulnerability
- **Detection Rule**: Alert on 'ConsoleLogin' where 'mfaAuthenticated != "true"' for privileged users

==================================================================


