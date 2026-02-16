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


**Installation and Data Preperattion**
_Setup of Virtual Enviroment_
In order to start the investigations with Splunk we will need a virtual environment using Ubuntu version 24.04. To accomplish this a virtual envrioment will need to be created within Microsoft Hyper-V.

1. Navigate to Ubuntu's website and download the 24.04 ISO image

2. Once the imagre has completed downloading you will need to use the quick create in Hyper-V to create a new Ubuntu VM instance.
   <img width="619" height="379" alt="image" src="https://github.com/user-attachments/assets/66b6b355-cf11-40b9-8ddd-ba9932488e8b" />

3. To use the ISO image you will need to select "Local Installation Source"
   <img width="290" height="359" alt="image" src="https://github.com/user-attachments/assets/623a8a32-df80-41f4-a67a-cce356798861" />

   A. Then select the ISO file, make sure to uncheck "This virtual machine will run Windows"
     <img width="349" height="103" alt="image" src="https://github.com/user-attachments/assets/c2cb2ec0-e9e7-4463-8f38-1aa7ba7064a2" />

   B. Once complete start the VM to load to the Ubuntu installation menu, you will select "try or install ubuntu" then press enter

   C. Once at the desktop, a window will appear asking you to install Ubuntu, you will proceed with the installation. No special installation instructions, basic installation is ok.


_Installation of Splunk program within Ubuntu VM environment._

1. Installation starts with the downloading of the Splunk program, to install you will need to sign up for an account within the Splunk website
   <img width="602" height="489" alt="image" src="https://github.com/user-attachments/assets/ef88f640-b995-4b25-9e9b-3acb716ca467" />

   A. To use the web portal you will need to register an account with your school email address, once registered you will have access to the tgz or deb files for installation.
   <img width="622" height="387" alt="image" src="https://github.com/user-attachments/assets/e0bc2f3f-49b1-403e-9873-ba6aaf9af89e" />
<img width="525" height="403" alt="image" src="https://github.com/user-attachments/assets/b45e800e-f8b6-43e9-a842-37cc392d0cb0" />
<img width="940" height="350" alt="image" src="https://github.com/user-attachments/assets/a6e86228-30c3-4103-85aa-c2d0dc6c2291" />
<img width="549" height="338" alt="image" src="https://github.com/user-attachments/assets/00495420-9651-4cf4-92ea-039a177ccb63" />

   B. The wget command that is provided will download the installation files to your Ubuntu instance.

3. 

**Guided Questions**
1. To find the IAM users that accessed an AWS service in Frothly's AWS enviroment we will undertake the following steps.

  A. First we will try and produce a list of all users that activley access the AWS enviroment
   <img width="970" height="131" alt="image" src="https://github.com/user-attachments/assets/d379c573-c40a-4738-9e85-af157fdd55ac" />

  B. Then with the log files, we will review the field 'userIdentity' by expanding the log and from here we can locate the user names of the users accessing AWS
  
  <img width="708" height="520" alt="image" src="https://github.com/user-attachments/assets/448c0403-ea4f-4a45-9958-970d6af52c0b" /> 
  <img width="531" height="526" alt="image" src="https://github.com/user-attachments/assets/a2ab6f3f-2cc3-4a24-a678-b0d31d3864b3" />
  <img width="526" height="516" alt="image" src="https://github.com/user-attachments/assets/964ec0fd-81b8-41f4-802c-4158414d364f" />
  <img width="649" height="573" alt="image" src="https://github.com/user-attachments/assets/af00503a-c5e1-45fd-aa32-906fe763c2a2" />

  C. From these logs we can assertain that the four users who accessed the AWS instance were; bstoll, btun, web_admin, and splunk_access

2. The field that one would use to alert of AWS API activity is userIdentity.sessionContext.attributes.mfaAuthenticated

  A. To start we will we will narrow down our search by obtaing a JSON file to evaluate and investigate for this field.
  <img width="855" height="111" alt="image" src="https://github.com/user-attachments/assets/922b97cc-b825-4cbf-9c5a-e5a21681054f" />

  B. From the JSON file we search for and investigate which records have the mfaAuthentication field set to 'false'
  <img width="979" height="568" alt="image" src="https://github.com/user-attachments/assets/6267ee9b-a6d0-43df-9922-0a3872bd0748" />

