"""
Sage Scanner Engine
Orchestrates all security checks and combines findings.
This is the heart of Sage.
"""

import sys
from typing import List, Dict, Any
from .aws_client import AWSClient
from .rules.public_s3 import check_public_s3_buckets

def scan_account(profile: str = "default", region: str = "us-east-1", verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Main scanning function - runs all security checks.
    
    Args:
        profile: AWS CLI profile name
        region: AWS region to scan
        verbose: Enable detailed output
        
    Returns:
        List of security findings, each with severity, description, remediation
    
    Example:
        findings = scan_account(profile="production", verbose=True)
        for finding in findings:
            print(f"{finding['severity']}: {finding['title']}")
    """
    
    findings = []
    
    if verbose:
        print("   🔧 Initializing Sage scanner...")
    
    try:
        # 1. Initialize AWS client
        client = AWSClient(profile=profile, region=region, verbose=verbose)
        
        # 2. Test connection and show account info
        account_info = client.test_connection()
        
        if verbose:
            print(f"\n   🎯 Target Account:")
            print(f"      ID:      {account_info['account_id']}")
            if account_info['account_alias']:
                print(f"      Alias:   {account_info['account_alias']}")
            print(f"      User:    {account_info['user_arn']}")
            print(f"      Profile: {account_info['profile']}")
            print(f"      Region:  {account_info['region']}")
            print()
        
        # 3. Run security checks
        if verbose:
            print("   🛡️  Running security checks...")
            print("   " + "=" * 50)
        
        # CHECK 1: Public S3 Buckets (Rule #1 - Most Critical)
        if verbose:
            print("\n   1️⃣  Checking for Public S3 Buckets...")
        
        s3_findings = check_public_s3_buckets(client)
        findings.extend(s3_findings)
        
        if verbose:
            if s3_findings:
                critical_s3 = sum(1 for f in s3_findings if f['severity'] == 'CRITICAL')
                print(f"      Found: {len(s3_findings)} issues ({critical_s3} critical)")
            else:
                print("      ✅ No public S3 buckets found")
        
        # CHECK 2: Admin Users without MFA (Placeholder - File 6)
        if verbose:
            print("\n   2️⃣  Checking Admin Users without MFA...")
            print("      (Rule implementation coming in File 6)")
        
        # Add placeholder finding to show structure
        findings.append({
            'id': 'PLACEHOLDER_MFA_CHECK',
            'severity': 'MEDIUM',
            'title': 'MFA Check Not Implemented Yet',
            'resource': 'arn:aws:iam::*:user/*',
            'description': 'This check will be implemented in File 6. It will find admin users without MFA enabled.',
            'remediation': 'Coming soon in the next update!',
            'impact': 'Placeholder - real check coming soon'
        })
        
        # CHECK 3: Wildcard Policies (Placeholder - File 7)
        if verbose:
            print("\n   3️⃣  Checking Wildcard Policies...")
            print("      (Rule implementation coming in File 7)")
        
        # CHECK 4: Open SSH/RDP Ports (Placeholder - File 8)
        if verbose:
            print("\n   4️⃣  Checking Security Groups for Open Ports...")
            print("      (Rule implementation coming in File 8)")
        
        # CHECK 5: Old Access Keys (Placeholder - File 9)
        if verbose:
            print("\n   5️⃣  Checking for Old Access Keys...")
            print("      (Rule implementation coming in File 9)")
        
        # 4. Add summary finding if no critical issues found
        if not any(f['severity'] == 'CRITICAL' for f in findings):
            findings.append({
                'id': 'SCAN_SUMMARY_NO_CRITICAL',
                'severity': 'INFO',
                'title': 'No Critical Issues Found',
                'resource': f"arn:aws:::{account_info['account_id']}",
                'description': (
                    f"Good news! Sage did not find any CRITICAL security issues "
                    f"in account {account_info['account_id']}.\n\n"
                    "However, this is a preliminary scan. Complete security assessment "
                    "requires all 5 checks to be implemented."
                ),
                'remediation': (
                    "Stay secure:\n"
                    "1. Complete Sage installation by updating to the latest version\n"
                    "2. Run regular security scans\n"
                    "3. Review AWS Security Hub findings\n"
                    "4. Enable AWS GuardDuty for threat detection"
                ),
                'impact': 'Your AWS account appears to have basic security controls in place.'
            })
        
        # 5. Add scan metadata
        scan_metadata = {
            'account_id': account_info['account_id'],
            'account_alias': account_info['account_alias'],
            'total_findings': len(findings),
            'critical_count': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
            'high_count': sum(1 for f in findings if f['severity'] == 'HIGH'),
            'medium_count': sum(1 for f in findings if f['severity'] == 'MEDIUM'),
            'low_count': sum(1 for f in findings if f['severity'] == 'LOW'),
            'info_count': sum(1 for f in findings if f['severity'] == 'INFO'),
        }
        
        # Add metadata as a special finding
        findings.append({
            'id': 'SCAN_METADATA',
            'severity': 'INFO',
            'title': 'Scan Summary',
            'resource': f"arn:aws:::{account_info['account_id']}",
            'description': 'Sage scan completed successfully.',
            'metadata': scan_metadata,
            'remediation': 'Review all findings above and take action as needed.',
            'impact': f"Scanned AWS account {account_info['account_id']}"
        })
        
        if verbose:
            print("\n   " + "=" * 50)
            print("   ✅ Scan completed successfully!")
        
        return findings
        
    except Exception as e:
        # If something goes wrong, return an error finding
        error_finding = {
            'id': 'SCAN_ERROR',
            'severity': 'HIGH',
            'title': 'Scan Failed',
            'resource': 'arn:aws:::unknown',
            'description': f"Sage scan failed with error: {str(e)}",
            'remediation': (
                "Troubleshooting steps:\n"
                "1. Check AWS credentials: sage configure\n"
                "2. Verify IAM permissions\n"
                "3. Check network connectivity\n"
                "4. Run with --verbose flag for details"
            ),
            'impact': 'Cannot complete security assessment due to scan failure.'
        }
        
        if verbose:
            print(f"\n   ❌ Scan failed: {str(e)}")
        
        return [error_finding]

def print_summary(findings: List[Dict[str, Any]]):
    """
    Print a simple summary of findings.
    
    Args:
        findings: List of security findings
    """
    # Extract metadata if present
    metadata_finding = next((f for f in findings if f['id'] == 'SCAN_METADATA'), None)
    
    if metadata_finding:
        metadata = metadata_finding.get('metadata', {})
        
        print("\n" + "="*60)
        print("SAGE SCAN SUMMARY")
        print("="*60)
        print(f"Account: {metadata.get('account_id', 'Unknown')}")
        if metadata.get('account_alias'):
            print(f"Alias:   {metadata['account_alias']}")
        print("-"*60)
        
        # Count findings by severity (excluding metadata and info)
        critical = metadata.get('critical_count', 0)
        high = metadata.get('high_count', 0)
        medium = metadata.get('medium_count', 0)
        low = metadata.get('low_count', 0)
        
        # Color-coded severity indicators
        if critical > 0:
            print(f"🔴 CRITICAL: {critical}  - Immediate action required!")
        if high > 0:
            print(f"🟠 HIGH:     {high}    - Fix within 24 hours")
        if medium > 0:
            print(f"🟡 MEDIUM:   {medium}  - Fix within 7 days")
        if low > 0:
            print(f"🔵 LOW:      {low}    - Consider fixing")
        
        total_issues = critical + high + medium + low
        if total_issues == 0:
            print("✅ No security issues found!")
        
        print("="*60)
    
    else:
        # Fallback if no metadata
        critical = sum(1 for f in findings if f['severity'] == 'CRITICAL' and f['id'] != 'SCAN_METADATA')
        high = sum(1 for f in findings if f['severity'] == 'HIGH' and f['id'] != 'SCAN_METADATA')
        medium = sum(1 for f in findings if f['severity'] == 'MEDIUM' and f['id'] != 'SCAN_METADATA')
        
        print(f"\n📊 Scan Results: {critical} critical, {high} high, {medium} medium issues found")

# Test function
def _test_scanner():
    """Test the scanner (for development only)"""
    print("Testing Sage Scanner...")
    
    try:
        # Run in test mode (will fail without AWS credentials, but that's OK)
        print("Running test scan (will fail without AWS credentials)...")
        
        # This will fail but show the error handling
        findings = scan_account(verbose=True)
        
        print(f"\nScanner test completed. Found {len(findings)} findings.")
        
        # Print summary
        print_summary(findings)
        
        return True
        
    except Exception as e:
        print(f"❌ Scanner test failed (expected without AWS setup): {str(e)}")
        return False

if __name__ == "__main__":
    # Only runs if file is executed directly
    _test_scanner()
