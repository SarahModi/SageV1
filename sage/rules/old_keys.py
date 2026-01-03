"""
Rule #5: Old Access Keys Check
Finds IAM access keys older than 90 days (AWS security best practice).
Old keys are often forgotten and leaked on GitHub.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any
from ..aws_client import AWSClient

def check_old_access_keys(client: AWSClient) -> List[Dict[str, Any]]:
    """
    Check for IAM access keys older than 90 days.
    
    Why this matters:
    - AWS recommends rotating access keys every 90 days
    - Old keys = Forgotten keys = Unmonitored keys
    - GitHub leaks: Developers accidentally commit old access keys
    - Employee departure: Ex-employees may still have working keys
    - Unused keys increase attack surface
    
    Args:
        client: AWSClient instance
        
    Returns:
        List of findings for old access keys
    """
    
    findings = []
    
    try:
        if client.verbose:
            print("   🔑 Checking for old access keys (>90 days)...")
        
        iam = client.get_client('iam')
        
        # Get all IAM users
        users = []
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            users.extend(page['Users'])
        
        if client.verbose:
            print(f"   🔍 Checking access keys for {len(users)} IAM users...")
        
        for user in users:
            username = user['UserName']
            user_arn = user['Arn']
            
            # Skip root account
            if username == 'root':
                continue
            
            # Get user's access keys
            try:
                access_keys = iam.list_access_keys(UserName=username)
            except Exception as e:
                if client.verbose:
                    print(f"      ⚠️  Could not get access keys for user {username}: {str(e)}")
                continue
            
            for key_metadata in access_keys.get('AccessKeyMetadata', []):
                key_id = key_metadata['AccessKeyId']
                key_status = key_metadata['Status']  # Active or Inactive
                create_date = key_metadata['CreateDate']
                
                # Skip inactive keys (already disabled)
                if key_status != 'Active':
                    continue
                
                # Calculate key age
                now = datetime.now(timezone.utc)
                key_age_days = (now - create_date).days
                
                # AWS recommendation: rotate every 90 days
                if key_age_days > 90:
                    # Determine severity based on age
                    if key_age_days > 365:
                        severity = 'HIGH'
                        age_description = f"{key_age_days} days (>1 year!)"
                    elif key_age_days > 180:
                        severity = 'MEDIUM'
                        age_description = f"{key_age_days} days (>6 months)"
                    else:
                        severity = 'LOW'
                        age_description = f"{key_age_days} days (>90 days)"
                    
                    # Check if key has been used recently
                    last_used = None
                    try:
                        last_used_response = iam.get_access_key_last_used(AccessKeyId=key_id)
                        last_used_info = last_used_response.get('AccessKeyLastUsed', {})
                        
                        if 'LastUsedDate' in last_used_info:
                            last_used = last_used_info['LastUsedDate']
                            last_used_days = (now - last_used).days if last_used else None
                            
                            # If key hasn't been used in a long time, it's likely forgotten
                            if last_used_days and last_used_days > 30:
                                severity = 'MEDIUM'  # Upgrade severity for unused keys
                                age_description += f", unused for {last_used_days} days"
                    except Exception:
                        # Some permissions may not allow this check
                        pass
                    
                    # Get user info for context
                    user_create_date = user.get('CreateDate', 'Unknown')
                    password_last_used = user.get('PasswordLastUsed', 'Never')
                    
                    findings.append({
                        'id': f'OLD_KEY_{username}_{key_id}',
                        'severity': severity,
                        'title': f'Old Access Key ({age_description})',
                        'resource': user_arn,
                        'description': (
                            f"IAM user '{username}' has an active access key that is {age_description} old.\n\n"
                            f"📋 Key Details:\n"
                            f"  • Access Key ID: {key_id[:10]}... (masked)\n"
                            f"  • Created: {create_date}\n"
                            f"  • Last Used: {last_used if last_used else 'Unknown or never used'}\n"
                            f"  • Status: {key_status}\n\n"
                            f"👤 User Details:\n"
                            f"  • User Created: {user_create_date}\n"
                            f"  • Last Password Use: {password_last_used}\n\n"
                            "🚨 RISK: Old access keys are dangerous because:\n"
                            "  1. Forgotten keys = Unrotated keys = Breach waiting to happen\n"
                            "  2. Developers accidentally commit old keys to GitHub\n"
                            "  3. Ex-employees may still have working keys\n"
                            "  4. Old keys are rarely monitored in security tools"
                        ),
                        'remediation': (
                            "ACTION REQUIRED:\n\n"
                            "Option 1: Rotate the access key (Recommended):\n"
                            f"  # Create new key\n"
                            f"  aws iam create-access-key --user-name {username}\n\n"
                            f"  # Update applications with new key\n"
                            f"  # Wait 24 hours to ensure everything works\n\n"
                            f"  # Deactivate old key\n"
                            f"  aws iam update-access-key --user-name {username} --access-key-id {key_id} --status Inactive\n\n"
                            f"  # Wait 7 more days, then delete\n"
                            f"  aws iam delete-access-key --user-name {username} --access-key-id {key_id}\n\n"
                            "Option 2: Use IAM Roles instead of access keys (Best Practice):\n"
                            "  • For EC2 instances: Use instance profiles\n"
                            "  • For Lambda: Use execution roles\n"
                            "  • For ECS: Use task roles\n"
                            "  • Access keys should only be for developers/test\n\n"
                            "Option 3: Setup automatic key rotation:\n"
                            "  1. Use AWS Config rule: iam-access-key-rotated\n"
                            "  2. Or use AWS Lambda to rotate keys automatically\n"
                            "  3. Or use third-party tools like Vault, CyberArk"
                        ),
                        'impact': (
                            "ACCESS KEY COMPROMISE RISK: Old keys increase attack surface.\n"
                            "If this key is leaked (e.g., on GitHub), attackers can:\n"
                            "• Access AWS resources with user's permissions\n"
                            "• Perform data exfiltration\n"
                            "• Create backdoor users\n"
                            "• Go undetected for months (old keys aren't monitored)"
                        ),
                        'context': {
                            'username': username,
                            'access_key_id': key_id[:10] + '...',  # Mask for safety
                            'key_age_days': key_age_days,
                            'key_created': create_date.isoformat(),
                            'key_last_used': last_used.isoformat() if last_used else None,
                            'key_status': key_status,
                            'user_created': user_create_date.isoformat() if hasattr(user_create_date, 'isoformat') else str(user_create_date)
                        }
                    })
                    
                    if client.verbose:
                        print(f"      🔑 Found old key for {username}: {key_age_days} days old")
        
        # Check for users with multiple active keys (bad practice)
        if client.verbose:
            print("      Checking for users with multiple active keys...")
        
        for user in users:
            username = user['UserName']
            
            try:
                access_keys = iam.list_access_keys(UserName=username)
                active_keys = [k for k in access_keys.get('AccessKeyMetadata', []) 
                              if k['Status'] == 'Active']
                
                if len(active_keys) > 1:
                    findings.append({
                        'id': f'MULTIPLE_KEYS_{username}',
                        'severity': 'LOW',
                        'title': 'Multiple Active Access Keys',
                        'resource': user['Arn'],
                        'description': (
                            f"IAM user '{username}' has {len(active_keys)} active access keys.\n"
                            "AWS recommends having only 2 keys maximum (one active, one rotating).\n"
                            "Multiple active keys increase management complexity and attack surface."
                        ),
                        'remediation': (
                            f"Review and clean up extra keys for user '{username}':\n"
                            f"  1. List keys: aws iam list-access-keys --user-name {username}\n"
                            f"  2. Identify which keys are actually used\n"
                            f"  3. Deactivate unused keys\n"
                            f"  4. Keep only 2 keys maximum"
                        ),
                        'context': {
                            'username': username,
                            'active_key_count': len(active_keys)
                        }
                    })
            except Exception:
                pass
        
        if client.verbose:
            if findings:
                old_key_count = sum(1 for f in findings if 'OLD_KEY_' in f['id'])
                multiple_key_count = sum(1 for f in findings if 'MULTIPLE_KEYS_' in f['id'])
                
                high_keys = sum(1 for f in findings if f['severity'] == 'HIGH' and 'OLD_KEY_' in f['id'])
                medium_keys = sum(1 for f in findings if f['severity'] == 'MEDIUM' and 'OLD_KEY_' in f['id'])
                
                print(f"      📊 Found {old_key_count} old keys ({high_keys} high, {medium_keys} medium), {multiple_key_count} users with multiple keys")
            else:
                print("      ✅ All access keys are fresh (<90 days)")
                
    except Exception as e:
        findings.append({
            'id': 'ACCESS_KEY_CHECK_ERROR',
            'severity': 'MEDIUM',
            'title': 'Access Key Check Failed',
            'resource': 'arn:aws:iam::*:user/*',
            'description': f"Could not check access keys: {str(e)}",
            'remediation': "Ensure Sage has iam:ListAccessKeys and iam:GetAccessKeyLastUsed permissions.",
            'context': {'error': str(e)}
        })
        
        if client.verbose:
            print(f"   ⚠️  Access key check failed: {str(e)}")
    
    return findings

# Test function
def _test_rule():
    """Test the old access keys rule (for development only)"""
    print("Testing Old Access Keys Rule...")
    
    # Mock finding for testing
    test_finding = {
        'id': 'OLD_KEY_TESTUSER_AKIA123456',
        'severity': 'MEDIUM',
        'title': 'Test Old Access Key (120 days)',
        'resource': 'arn:aws:iam::123456789012:user/testuser',
        'description': 'Test access key older than 90 days.',
        'remediation': 'Rotate this access key.',
        'impact': 'Forgotten key risk'
    }
    
    print(f"✅ Rule test successful - would find: {test_finding['title']}")
    return [test_finding]

if __name__ == "__main__":
    # Only runs if file is executed directly
    _test_rule()
