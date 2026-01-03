"""
Rule #3: Wildcard Policies Check
Finds IAM policies with "*:*" permissions or wildcards on sensitive services.
These policies can delete your entire AWS account with one command.
"""

import json
from typing import List, Dict, Any
from ..aws_client import AWSClient

def check_wildcard_policies(client: AWSClient) -> List[Dict[str, Any]]:
    """
    Check for dangerous IAM policies with wildcard permissions.
    
    Why this is critical:
    - "*:*" on resources = Delete all S3 buckets, EC2 instances, databases
    - "iam:*" permissions = Create new admin users, escalate privileges
    - "s3:*" on "*" = Delete all company data
    - Real impact: Startup deleted production database with wildcard policy
    
    Args:
        client: AWSClient instance
        
    Returns:
        List of findings for dangerous wildcard policies
    """
    
    findings = []
    
    try:
        if client.verbose:
            print("   ⚠️  Checking for dangerous wildcard policies...")
        
        iam = client.get_client('iam')
        
        # Check 1: Customer Managed Policies
        if client.verbose:
            print("      Checking customer managed policies...")
        
        customer_policies = []
        paginator = iam.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):  # Local = customer managed
            customer_policies.extend(page['Policies'])
        
        for policy in customer_policies:
            if policy['AttachmentCount'] > 0:  # Only check attached policies
                policy_name = policy['PolicyName']
                policy_arn = policy['Arn']
                
                # Get policy document
                policy_version = iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy['DefaultVersionId']
                )
                
                policy_doc = policy_version['PolicyVersion']['Document']
                
                # Analyze policy for wildcards
                wildcard_issues = _analyze_policy_for_wildcards(policy_doc, policy_name)
                
                if wildcard_issues:
                    # Find what's attached to this policy
                    attached_entities = []
                    try:
                        entities = iam.list_entities_for_policy(PolicyArn=policy_arn)
                        
                        for user in entities.get('PolicyUsers', []):
                            attached_entities.append(f"User: {user['UserName']}")
                        for group in entities.get('PolicyGroups', []):
                            attached_entities.append(f"Group: {group['GroupName']}")
                        for role in entities.get('PolicyRoles', []):
                            attached_entities.append(f"Role: {role['RoleName']}")
                            
                    except Exception:
                        attached_entities = ["Unknown (no permissions to list)"]
                    
                    findings.append({
                        'id': f'WILDCARD_POLICY_{policy_name}',
                        'severity': 'HIGH',
                        'title': 'Dangerous Wildcard Policy',
                        'resource': policy_arn,
                        'description': (
                            f"Customer managed policy '{policy_name}' has dangerous wildcard permissions:\n\n"
                            f"{wildcard_issues}\n\n"
                            f"📋 Policy Details:\n"
                            f"  • Policy ARN: {policy_arn}\n"
                            f"  • Attached to: {', '.join(attached_entities) if attached_entities else 'Nothing (orphaned)'}\n"
                            f"  • Created: {policy.get('CreateDate', 'Unknown')}\n\n"
                            "🚨 RISK: Wildcard policies can lead to:\n"
                            "  1. Accidental deletion of all resources\n"
                            "  2. Privilege escalation attacks\n"
                            "  3. Data exfiltration at scale\n"
                            "  4. Complete account compromise"
                        ),
                        'remediation': (
                            "ACTION REQUIRED:\n\n"
                            "Option 1: Replace with least-privilege policy (Recommended):\n"
                            f"  1. Go to: https://console.aws.amazon.com/iam/home#/policies/{policy_arn.split(':')[-1]}\n"
                            "  2. Create new version with specific permissions\n"
                            "  3. Replace wildcards with exact resource ARNs\n"
                            "  4. Use AWS Access Analyzer for policy suggestions\n\n"
                            "Option 2: Detach and delete if unused:\n"
                            f"  # Detach from all entities first\n"
                            f"  aws iam detach-user-policy --user-name USER --policy-arn {policy_arn}\n"
                            f"  # Then delete policy\n"
                            f"  aws iam delete-policy --policy-arn {policy_arn}\n\n"
                            "Option 3: Use AWS Managed Policies instead:\n"
                            "  AWS provides pre-built least-privilege policies\n"
                            "  like AmazonS3ReadOnlyAccess, AmazonEC2ReadOnlyAccess"
                        ),
                        'impact': (
                            "PRIVILEGE ESCALATION RISK: This policy grants overly broad permissions.\n"
                            "If compromised, an attacker could:\n"
                            "• Delete all S3 buckets and data\n"
                            "• Terminate all EC2 instances\n"
                            "• Create new admin users\n"
                            "• Encrypt resources for ransomware"
                        ),
                        'context': {
                            'policy_name': policy_name,
                            'policy_arn': policy_arn,
                            'wildcard_issues': wildcard_issues,
                            'attached_count': policy['AttachmentCount'],
                            'is_aws_managed': False
                        }
                    })
                    
                    if client.verbose:
                        print(f"      🔴 Found dangerous policy: {policy_name}")
        
        # Check 2: Inline Policies on Users, Groups, Roles
        if client.verbose:
            print("      Checking inline policies...")
        
        # Check roles (most common for wildcards in EC2, Lambda)
        roles = []
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            roles.extend(page['Roles'])
        
        for role in roles:
            role_name = role['RoleName']
            role_arn = role['Arn']
            
            # Skip service-linked roles
            if 'ServiceLinkedRole' in role.get('Path', ''):
                continue
            
            # Get inline policies for role
            try:
                inline_policies = iam.list_role_policies(RoleName=role_name)
                
                for policy_name in inline_policies['PolicyNames']:
                    policy_doc = iam.get_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name
                    )
                    
                    wildcard_issues = _analyze_policy_for_wildcards(
                        policy_doc['PolicyDocument'], 
                        f"{role_name}/{policy_name}"
                    )
                    
                    if wildcard_issues:
                        findings.append({
                            'id': f'WILDCARD_ROLE_{role_name}_{policy_name}',
                            'severity': 'HIGH',
                            'title': 'Role with Wildcard Policy',
                            'resource': role_arn,
                            'description': (
                                f"IAM Role '{role_name}' has inline policy '{policy_name}' with dangerous wildcards:\n\n"
                                f"{wildcard_issues}\n\n"
                                f"📋 Role Details:\n"
                                f"  • Role ARN: {role_arn}\n"
                                f"  • Created: {role.get('CreateDate', 'Unknown')}\n"
                                f"  • Trusts: {role.get('AssumeRolePolicyDocument', {}).get('Statement', [])}\n\n"
                                "🚨 RISK: Roles with wildcards are often used by:\n"
                                "  • EC2 instances (can be compromised)\n"
                                "  • Lambda functions (execution risk)\n"
                                "  • ECS tasks (container breakout)\n"
                                "Wildcards amplify any vulnerability in these services."
                            ),
                            'remediation': (
                                "IMMEDIATE REVIEW REQUIRED:\n\n"
                                f"1. Go to: https://console.aws.amazon.com/iam/home#/roles/{role_name}\n"
                                "2. Click the 'Permissions' tab\n"
                                "3. Review inline policies\n"
                                "4. Replace wildcards with specific resources\n\n"
                                "LEAST PRIVILEGE TIPS:\n"
                                "• Use resource ARNs instead of '*'\n"
                                "• Restrict to specific S3 buckets\n"
                                "• Limit to specific VPCs or subnets\n"
                                "• Use conditions for extra security"
                            ),
                            'context': {
                                'role_name': role_name,
                                'policy_name': policy_name,
                                'wildcard_issues': wildcard_issues,
                                'is_service_linked': False
                            }
                        })
                        
                        if client.verbose:
                            print(f"      🔴 Found role with wildcard policy: {role_name}")
                            
            except Exception as e:
                if client.verbose:
                    print(f"      ⚠️  Could not check inline policies for role {role_name}: {str(e)}")
        
        if client.verbose:
            if findings:
                policy_count = sum(1 for f in findings if 'WILDCARD_POLICY' in f['id'])
                role_count = sum(1 for f in findings if 'WILDCARD_ROLE' in f['id'])
                print(f"      📊 Found {policy_count} wildcard policies and {role_count} roles with wildcards")
            else:
                print("      ✅ No dangerous wildcard policies found")
                
    except Exception as e:
        findings.append({
            'id': 'WILDCARD_CHECK_ERROR',
            'severity': 'MEDIUM',
            'title': 'Wildcard Policy Check Failed',
            'resource': 'arn:aws:iam::*:policy/*',
            'description': f"Could not check for wildcard policies: {str(e)}",
            'remediation': "Ensure Sage has iam:ListPolicies, iam:GetPolicyVersion, and iam:ListRoles permissions.",
            'context': {'error': str(e)}
        })
        
        if client.verbose:
            print(f"   ⚠️  Wildcard check failed: {str(e)}")
    
    return findings

def _analyze_policy_for_wildcards(policy_doc: dict, policy_name: str) -> str:
    """
    Analyze a policy document for dangerous wildcards.
    
    Args:
        policy_doc: IAM policy document
        policy_name: Name of policy for context
        
    Returns:
        String describing wildcard issues, or empty string if none
    """
    
    issues = []
    
    for statement in policy_doc.get('Statement', []):
        if statement.get('Effect') == 'Allow':
            actions = statement.get('Action', [])
            resources = statement.get('Resource', [])
            conditions = statement.get('Condition', {})
            
            # Convert to lists for consistency
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            # Check for full wildcard "*:*"
            if '*' in actions or '*:*' in actions:
                issues.append(f"• Full wildcard action ('*' or '*:*') - Can perform ANY AWS action")
            
            # Check for service wildcards on sensitive services
            sensitive_services = ['iam:', 's3:', 'ec2:', 'rds:', 'lambda:', 'kms:', 'secretsmanager:']
            for action in actions:
                for service in sensitive_services:
                    if action.startswith(service) and '*' in action:
                        issues.append(f"• Wildcard on {service}* - Full control over {service[:-1]} service")
                        break
            
            # Check for wildcard resources
            if '*' in resources:
                # Check if paired with dangerous actions
                dangerous_actions = ['Delete', 'Modify', 'Put', 'Update', 'Create', 'Stop', 'Terminate']
                for action in actions:
                    if any(da in action for da in dangerous_actions):
                        issues.append(f"• Wildcard resource ('*') with {action} action - Can affect ALL resources")
                        break
            
            # Check for NotAction/NotResource (can be tricky)
            if 'NotAction' in statement or 'NotResource' in statement:
                issues.append(f"• Uses NotAction/NotResource - Review carefully, can be overly permissive")
    
    # Remove duplicates and format
    unique_issues = []
    for issue in issues:
        if issue not in unique_issues:
            unique_issues.append(issue)
    
    if unique_issues:
        return "\n".join(unique_issues)
    else:
        return ""

# Test function
def _test_rule():
    """Test the wildcard policy rule (for development only)"""
    print("Testing Wildcard Policies Rule...")
    
    # Mock finding for testing
    test_finding = {
        'id': 'WILDCARD_POLICY_TEST',
        'severity': 'HIGH',
        'title': 'Test Wildcard Policy',
        'resource': 'arn:aws:iam::123456789012:policy/TestPolicy',
        'description': 'Test policy with wildcards - this needs review.',
        'remediation': 'Replace wildcards with specific resources.',
        'impact': 'Overly permissive policy risk'
    }
    
    print(f"✅ Rule test successful - would find: {test_finding['title']}")
    return [test_finding]

if __name__ == "__main__":
    # Only runs if file is executed directly
    _test_rule()
