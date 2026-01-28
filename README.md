# COMP3010HK-CW2

Introduction
Frothly Beverages operates a cloud-first production stack monitored by 24 x 7 Security Operations Center (SOC) whose charter is to detect, triage and respond to threats against AWS-hosted intellectual property and customer data. A single misconfigured S3 buck can expose an entire brand to regulatory finds and reputational damage. The BOTSv3 exrecise compresses that risk senario into a safe Splunk sandbox, giving Frothly's SOC a timed rehearsal against a week of CloudTrail, S3, osquery and Windows telemetry. Using SPL searches and JSON field extractions, we identify six key artefacts: IAM principals, MFA absence flags, processor models, public-access event IDs, uploaded text files and anomalous OS editions. All conclusions are traceable to the raw events; no external telemetry or remediation actions are within the scope.

SOC Roles and Incident Handling Reflection
BOTSv3 exercise mirrors a real-world could breach and maps cleanly to a tiered SOC operating model.
- Tier 1: analyst performs initial triage, they observe CloudTrail "PutBucketAcl" alert, confirm the "AllUsers" grant, and escalate within SLA.
- Tier 2: analyst pivot across aws:cloudtrail, aws:s3:accesslogs and winhostmon to correlate IAM user bstoll, the MFA gap, the OPEN_BUCKET_PLEASE_FIX.txt upload and the anomalous Windows 10 Enterprise host, then draft a incident ticket with IOCs.
- Tier 3: Detection-Engineering builds retro-active signatures (e.g., userIdentity.session.Context.attributes.mfaAuthenticated=false coupled with PutBucketAcl) and updates the SIEM to prevent recurrence

NIST phases in play:
- Prevention: MFA enforcement and least-privilage IAM policies would have blocked the ACL change.
- Detection: the aws:cloudtrail source type fired within minutes, satisfying MTTD goals.
- Response: bucket ACL was reverted and access logs confirmed no exfiltration before containment.
- Recovery: validation searches ensured the bucket remained private and the text object was deleted; lessons learned were fed back into policy hardening and staff training, closing the loop on continuous security improvement.
