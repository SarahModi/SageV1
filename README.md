# SageV1
AWS Security Scanner. Find the 5 misconfigurations that actually cause breaches.

# 🚀 Quick Install

```bash
pip install git+https://github.com/SarahModi/SageV1.git

```
# Usage
## Configure AWS (one time)
aws configure --profile your-profile

## Scan your account
sage scan --profile your-profile

## Get help
sage --help

# What Sage Finds
🔴 Public S3 buckets (Capital One breach)

🔴 Admin users without MFA

⚠️ Wildcard policies

🚪 Open SSH/RDP ports

🔑 Old access keys
