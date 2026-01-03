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

# ONE-TIME SETUP
- python3 -m venv venv          # Create virtual environment
- source venv/bin/activate      # Activate it
- git clone https://github.com/SarahModi/sagev1.git
- cd sagev1
- pip install -e .              # Install Sage
- aws configure --profile my-aws-profile

# WHENEVER YOU WANT TO SCAN
- source venv/bin/activate      # If venv not active
- sage scan --profile my-aws-profile

# OPTIONAL FLAGS
- sage scan --profile my-aws-profile --verbose   # See details
- sage scan --profile my-aws-profile --quiet     # Only findings
- sage scan --format json                        # JSON output
- sage scan --help                               # All options
  

# Exit Codes (for CI/CD):
0 = No critical issues

1 = Critical issues found
