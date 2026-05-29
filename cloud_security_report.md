# Cloud Security Posture Report

Overall risk rating: **Critical**
Risk score: **64**
Findings: **10**

## Executive Summary

This report reviews AWS-style inventory, security group rules, and VPC Flow Log samples. Findings are prioritized by likely business impact, remediation urgency, and CIS AWS Foundations alignment.

## Compliance Coverage

- Framework: CIS AWS Foundations Benchmark v1.4.0 alignment
- Note: This project performs educational checks against sample data and is not a substitute for a full CIS audit.

## Findings

### 1. Admin IAM user without MFA

- Severity: **CRITICAL**
- Resource: `break-glass-admin`
- Evidence: break-glass-admin has AdministratorAccess and mfa_enabled=false.
- Recommendation: Require MFA for all privileged identities and prefer short-lived roles.
- Compliance: CIS AWS Foundations Benchmark v1.4.0 1.10 - Ensure MFA is enabled for all users that have a console password; CIS AWS Foundations Benchmark v1.4.0 1.16 - Ensure IAM policies that allow full administrative privileges are not attached

### 2. Public SSH access

- Severity: **CRITICAL**
- Resource: `sg-002`
- Evidence: sg-002 allows 0.0.0.0/0 to TCP/22.
- Recommendation: Restrict administrative access to a VPN, bastion host, or approved office IP range.
- Compliance: CIS AWS Foundations Benchmark v1.4.0 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports

### 3. Repeated rejected public SSH traffic

- Severity: **HIGH**
- Resource: `10.0.2.15:22`
- Evidence: 77 rejected packets from public IP space targeted TCP/22.
- Recommendation: Confirm the instance is not internet-facing and investigate repeated scan sources.
- Compliance: CIS AWS Foundations Benchmark v1.4.0 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports

### 4. Repeated rejected public RDP traffic

- Severity: **HIGH**
- Resource: `10.0.3.44:3389`
- Evidence: 54 rejected packets from public IP space targeted TCP/3389.
- Recommendation: Confirm the instance is not internet-facing and investigate repeated scan sources.
- Compliance: CIS AWS Foundations Benchmark v1.4.0 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports

### 5. Public MySQL access

- Severity: **HIGH**
- Resource: `sg-003`
- Evidence: sg-003 allows 0.0.0.0/0 to TCP/3306.
- Recommendation: Place the service on private subnets and limit access by source security group.
- Compliance: No direct CIS mapping; included as a security best-practice finding.

### 6. Public S3 bucket

- Severity: **HIGH**
- Resource: `student-portfolio-public-assets`
- Evidence: student-portfolio-public-assets has public_access=true.
- Recommendation: Enable S3 Block Public Access and review bucket policies.
- Compliance: CIS AWS Foundations Benchmark v1.4.0 2.1.5 - Ensure S3 buckets are configured with Block Public Access

### 7. Old IAM access key

- Severity: **MEDIUM**
- Resource: `break-glass-admin`
- Evidence: break-glass-admin key age is 120 days.
- Recommendation: Rotate long-lived access keys and move automation to IAM roles where possible.
- Compliance: CIS AWS Foundations Benchmark v1.4.0 1.14 - Ensure access keys are rotated every 90 days or less

### 8. Old IAM access key

- Severity: **MEDIUM**
- Resource: `readonly-auditor`
- Evidence: readonly-auditor key age is 145 days.
- Recommendation: Rotate long-lived access keys and move automation to IAM roles where possible.
- Compliance: CIS AWS Foundations Benchmark v1.4.0 1.14 - Ensure access keys are rotated every 90 days or less

### 9. Bucket not encrypted with customer-managed KMS

- Severity: **MEDIUM**
- Resource: `student-portfolio-app-logs`
- Evidence: student-portfolio-app-logs encryption is None.
- Recommendation: Use SSE-KMS for sensitive data and rotate keys according to policy.
- Compliance: No direct CIS mapping; included as a security best-practice finding.

### 10. Bucket not encrypted with customer-managed KMS

- Severity: **MEDIUM**
- Resource: `student-portfolio-public-assets`
- Evidence: student-portfolio-public-assets encryption is AES256.
- Recommendation: Use SSE-KMS for sensitive data and rotate keys according to policy.
- Compliance: No direct CIS mapping; included as a security best-practice finding.
