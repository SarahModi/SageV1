# Sage - AWS Security Scanner

**Find the 5 AWS misconfigurations that actually cause breaches.**



##  Quick Start


# 1. Create virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

# 2. Install Sage
```
pip install git+https://github.com/SarahModi/SageV1.git
```
# 3. Configure AWS
```
aws configure --profile your-profile
```
# 4. Scan
```
sage scan --profile your-profile
```

# What Sage Finds
Sage doesn't overwhelm you with 500 findings. It finds the 5 critical issues that cause real breaches:

🔴 Public S3 buckets - Like the Capital One breach (106M records)

🔴 Admin users without MFA - One password away from total takeover

⚠️ Wildcard policies - Could delete all your data

🚪 Open SSH/RDP ports - Constantly scanned by hackers

🔑 Old access keys - Often forgotten and leaked on GitHub

# Usage
Basic Commands
```bash
# Scan AWS account
sage scan
sage scan --profile production
```
Get Help
```
sage --help
sage scan --help
```
Show Version
```
sage version
```
# AWS setup help
```
sage configure
```
Advanced Options
```
# Different output formats
sage scan --format json        # JSON for CI/CD
sage scan --format csv         # CSV for spreadsheets
sage scan --output results.json # Save to file
```
# Verbosity control
```
sage scan --verbose           # Show detailed progress
sage scan --quiet             # Only show findings
```
# Region selection
```
sage scan --region us-west-2  # Scan specific region
```


# Integration

## CI/CD Pipeline

GitHub Actions example
- name: AWS Security Scan
  run: |
    pip install sage-iam
    sage scan --format json --output security-scan.json
  ### Exit code 1 if critical issues found
