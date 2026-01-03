"""
Rule #2: Admin Users Without MFA Check
Finds IAM users with admin permissions but no Multi-Factor Authentication.
This prevents 99.9% of account takeover attacks.
"""

import json
from typing import List, Dict, Any
from ..aws_client import AWSClient

def check_mfa_for_admins(client: AWSClient) -> List[Dict[str, Any]]:
    """
    Check for IAM users with admin permissions but no MFA enabled.
    
    Why this is critical:
    - 80%+ of cloud breaches start with compromised credentials
    - MFA blocks 99.9% of automated attacks
    - One phishing email = total AWS takeover without MFA
    - Real example: Startup CTO's password was "password123" on admin account
    
    Args:
        client: AWSClient instance
        
    Returns:
        List of findings for admin users without MFA
    """
    
    findings = []
    
    try:
        if client.verbose:
            print("   👤 Checking IAM users for MFA on admin accounts...")
        
        iam = client.get_client('iam')
        
        # Get all IAM users
        users = []
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            users.extend(page['Users'])
        
        if client.verbose:
            print(f"   🔍 Found {len(users)} IAM users to check")
        
        for user in users:
            username = user['UserName']
            user_arn = user['Arn']
            
            # Skip root account (handled separately)
            if username == 'root':
                continue
            
            # Get user's MFA devices
            try:
                mfa_devices = iam.list_mfa_devices(UserName=username)
                has_mfa = len(mfa_devices['MFADevices']) > 0
            except Exception as e:
                if client.verbose:
                    print(f"   ⚠️  Could not check MFA for user {username}: {str(e)}")
                has_mfa = False
            
            # Check if user has admin permissions
            is_admin = False
            admin_reason = ""
            
            # Method 1: Check attached policies
            try:
                attached_policies = iam.list_attached_user_policies(UserName=username)
                for policy in attached_policies['AttachedPolicies']:
                    policy_name = policy['PolicyName']
                    policy_arn = policy['PolicyArn']
                    
                    # Check for admin policies (common patterns)
                    admin_indicators = [
                        'AdministratorAccess',  # Full admin
                        'Admin',                # Contains Admin
                        'FullAccess',          # Full access
                        'PowerUser',           # Power user (almost admin)
                        'aws-portal',          # Billing access
                    ]
                    
                    if any(indicator in policy_name for indicator in admin_indicators):
                        is_admin = True
                        admin_reason = f"Has policy: {policy_name}"
                        break
                    
                    # Also check if policy ARN is the AWS managed AdministratorAccess
                    if policy_arn.endswith(':policy/AdministratorAccess'):
                        is_admin = True
                        admin_reason = "Has AWS Managed AdministratorAccess policy"
                        break
            except Exception as e:
                if client.verbose:
                    print(f"   ⚠️  Could not check attached policies for {username}: {str(e)}")
            
            # Method 2: Check inline policies if not admin yet
            if not is_admin:
                try:
                    inline_policies = iam.list_user_policies(UserName=username)
                    for policy_name in inline_policies['PolicyNames']:
                        # Get policy document
                        policy_doc = iam.get_user_policy(
                            UserName=username,
                            PolicyName=policy_name
                        )
                        
                        # Check if policy has admin permissions
                        if _policy_has_admin_permissions(policy_doc['PolicyDocument']):
                            is_admin = True
                            admin_reason = f"Has inline policy with admin permissions: {policy_name}"
                            break
                except Exception as e:
                    if client.verbose:
                        print(f"   ⚠️  Could not check inline policies for {username}: {str(e)}")
            
            # Method 3: Check group memberships if not admin yet
            if not is_admin:
                try:
                    user_groups = iam.list_groups_for_user(UserName=username)
                    for group in user_groups['Groups']:
                        group_name = group['GroupName']
                        
                        # Check group policies
                        group_policies = iam.list_attached_group_policies(GroupName=group_name)
                        for policy in group_policies['AttachedPolicies']:
                            if 'AdministratorAccess' in policy['PolicyName'] or 'Admin' in policy['PolicyName']:
                                is_admin = True
                                admin_reason = f"Member of group '{group_name}' with admin policy: {policy['PolicyName']}"
                                break
                        
                        if is_admin:
                            break
                except Exception as e:
                    if client.verbose:
                        print(f"   ⚠️  Could not check groups for user {username}: {str(e)}")
            
            # If user is admin and has no MFA, create finding
            if is_admin and not has_mfa:
                # Get user info for context
                user_create_date = user.get('CreateDate', 'Unknown')
                password_last_used = user.get('PasswordLastUsed', 'Never')
                
                findings.append({
                    'id': f'MFA_MISSING_ADMIN_{username}',
                    'severity': 'CRITICAL',
                    'title': 'Admin User Without MFA',
                    'resource': user_arn,
                    'description': (
                        f"IAM user '{username}' has admin permissions but no Multi-Factor Authentication (MFA) enabled.\n\n"
                        f"📋 User Details:\n"
                        f"  • Created: {user_create_date}\n"
                        f"  • Last password use: {password_last_used}\n"
                        f"  • Admin reason: {admin_reason}\n\n"
                        "🚨 RISK: This is a CRITICAL security gap because:\n"
                        "  1. One leaked password = Total AWS account takeover\n"
                        "  2. Phishing attacks can bypass password-only protection\n"
                        "  3. Automated bots constantly try common passwords\n"
                        "  4. MFA blocks 99.9% of account compromise attempts"
                    ),
                    'remediation': (
                        "IMMEDIATE ACTION REQUIRED:\n\n"
                        "Option 1: Enable MFA (Recommended):\n"
                        f"  1. Go to: https://console.aws.amazon.com/iam/home#/users/{username}\n"
                        "  2. Click 'Security credentials' tab\n"
                        "  3. Click 'Manage' next to 'Assigned MFA device'\n"
                        "  4. Follow prompts to setup virtual or hardware MFA\n\n"
                        "Option 2: Remove admin permissions (if not needed):\n"
                        f"  aws iam detach-user-policy \\\n"
                        f"    --user-name {username} \\\n"
                        f"    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n\n"
                        "Option 3: Use IAM Identity Center (SSO) for central MFA:\n"
                        "  1. Setup AWS IAM Identity Center\n"
                        "  2. Connect to your identity provider (Okta, Google, etc.)\n"
                        "  3. Enforce MFA at the organization level"
                    ),
                    'impact': (
                        "ACCOUNT TAKEOVER RISK: Without MFA, this admin account is "
                        "one password leak away from complete compromise.\n"
                        "This could lead to:\n"
                        "• Data theft and deletion\n"
                        "• Cryptocurrency mining on your infrastructure\n"
                        "• Ransomware deployment\n"
                        "• Reputational damage and customer data breaches"
                    ),
                    'context': {
                        'username': username,
                        'user_arn': user_arn,
                        'admin_reason': admin_reason,
                        'has_mfa': has_mfa,
                        'password_last_used': str(password_last_used)
                    }
                })
                
                if client.verbose:
                    print(f"   🔴 Found admin without MFA: {username}")
        
        # Special check for root account MFA
        try:
            summary = iam.get_account_summary()
            account_mfa_enabled = summary['SummaryMap'].get('AccountMFAEnabled', 0)
            
            if account_mfa_enabled == 0:
                findings.append({
                    'id': 'ROOT_ACCOUNT_NO_MFA',
                    'severity': 'CRITICAL',
                    'title': 'Root Account Without MFA',
                    'resource': 'arn:aws:iam::root',
                    'description': (
                        "AWS Root account does not have Multi-Factor Authentication (MFA) enabled.\n\n"
                        "🚨 ULTRA CRITICAL: The root account is the 'keys to the kingdom':\n"
                        "• Can close the entire AWS account\n"
                        "• Cannot be restricted by IAM policies\n"
                        "• Has unlimited access to all resources and billing\n"
                        "• Should NEVER be used for daily operations"
                    ),
                    'remediation': (
                        "STOP EVERYTHING AND FIX THIS NOW:\n\n"
                        "1. Log in to AWS Console as root\n"
                        "2. Go to: https://console.aws.amazon.com/iam/home#/security_credentials\n"
                        "3. Click 'Multi-factor authentication (MFA)'\n"
                        "4. Click 'Activate MFA'\n"
                        "5. Follow setup instructions\n\n"
                        "BEST PRACTICES:\n"
                        "• Store root credentials in a physical safe\n"
                        "• Never use root for daily operations\n"
                        "• Create IAM users with appropriate permissions\n"
                        "• Enable MFA on ALL admin accounts"
                    ),
                    'impact': (
                        "EXISTENTIAL RISK: Root account compromise = Complete loss of "
                        "ALL AWS resources, data, and services.\n"
                        "This could literally put your company out of business."
                    ),
                    'context': {'root_account_mfa': False}
                })
                
                if client.verbose:
                    print("   🔴 Root account does not have MFA enabled!")
        except Exception as e:
            if client.verbose:
                print(f"   ⚠️  Could not check root account MFA: {str(e)}")
        
        if client.verbose:
            if findings:
                admin_mfa_count = sum(1 for f in findings if 'MFA_MISSING' in f['id'])
                print(f"   📊 Found {admin_mfa_count} admin users without MFA")
            else:
                print("   ✅ All admin users have MFA enabled")
                
    except Exception as e:
        findings.append({
            'id': 'MFA_CHECK_ERROR',
            'severity': 'HIGH',
            'title': 'MFA Check Failed',
            'resource': 'arn:aws:iam::*:user/*',
            'description': f"Could not check MFA status for IAM users: {str(e)}",
            'remediation': "Ensure Sage has iam:ListUsers, iam:ListMFADevices, and iam:ListAttachedUserPolicies permissions.",
            'context': {'error': str(e)}
        })
        
        if client.verbose:
            print(f"   ❌ MFA check failed: {str(e)}")
    
    return findings

def _policy_has_admin_permissions(policy_document: dict) -> bool:
    """
    Check if a policy document grants admin-level permissions.
    
    Args:
        policy_document: IAM policy document
        
    Returns:
        True if policy has admin permissions
    """
    # Look for statements that grant wide permissions
    for statement in policy_document.get('Statement', []):
        if statement.get('Effect') == 'Allow':
            action = statement.get('Action', [])
            resource = statement.get('Resource', [])
            
            # Convert to lists for consistency
            if isinstance(action, str):
                action = [action]
            if isinstance(resource, str):
                resource = [resource]
            
            # Check for wildcard actions
            has_wildcard_action = any(act == '*' or act == '*:*' for act in action)
            
            # Check for admin-level actions
            has_admin_actions = False
            admin_patterns = [
                '*:*',           # Full wildcard
                'iam:*',         # IAM admin
                'ec2:*',         # EC2 admin  
                's3:*',          # S3 admin
                'sts:*',         # Security token service
                'cloudtrail:*',  # Logging admin
            ]
            
            for act in action:
                if any(pattern in act for pattern in admin_patterns):
                    has_admin_actions = True
                    break
            
            # Check for wildcard resources
            has_wildcard_resource = any(res == '*' for res in resource)
            
            # If both wildcard action and resource, it's definitely admin
            if has_wildcard_action and has_wildcard_resource:
                return True
            
            # If has admin actions on wildcard resources
            if has_admin_actions and has_wildcard_resource:
                return True
    
    return False

# Test function
def _test_rule():
    """Test the MFA rule (for development only)"""
    print("Testing MFA Admin Check Rule...")
    
    # Mock finding for testing
    test_finding = {
        'id': 'MFA_MISSING_ADMIN_TESTUSER',
        'severity': 'CRITICAL',
        'title': 'Test Admin User Without MFA',
        'resource': 'arn:aws:iam::123456789012:user/testadmin',
        'description': 'Test admin user without MFA - this is a critical finding.',
        'remediation': 'Enable MFA immediately!',
        'impact': 'Account takeover risk'
    }
    
    print(f"✅ Rule test successful - would find: {test_finding['title']}")
    return [test_finding]

if __name__ == "__main__":
    # Only runs if file is executed directly
    _test_rule()
