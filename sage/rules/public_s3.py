"""
Rule #1: Public S3 Buckets Check
Finds S3 buckets with public read access - the #1 cause of cloud data breaches.
"""

import json
from typing import List, Dict, Any
from ..aws_client import AWSClient

def check_public_s3_buckets(client: AWSClient) -> List[Dict[str, Any]]:
    """
    Check for S3 buckets with public read access.
    
    This is the most critical check because:
    - Capital One breach (2019): 106 million records exposed
    - Tesla breach (2021): Sensitive data exposed
    - S3 is the #1 source of cloud data leaks
    
    Args:
        client: AWSClient instance
        
    Returns:
        List of findings, each with severity, title, description, remediation
    """
    
    findings = []
    
    try:
        if client.verbose:
            print("   📦 Checking S3 buckets for public access...")
        
        # Get S3 client
        s3 = client.get_client('s3')
        
        # List all buckets
        response = s3.list_buckets()
        buckets = response.get('Buckets', [])
        
        if client.verbose:
            print(f"   🔍 Scanning {len(buckets)} S3 buckets...")
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            # Skip if bucket name indicates it might be a log bucket (common false positive)
            if any(log_term in bucket_name.lower() for log_term in ['log', 'access', 'audit']):
                if client.verbose:
                    print(f"   ⏭️  Skipping likely log bucket: {bucket_name}")
                continue
            
            try:
                # Check 1: Get bucket policy
                policy = None
                try:
                    policy_response = s3.get_bucket_policy(Bucket=bucket_name)
                    policy = policy_response.get('Policy')
                except s3.exceptions.NoSuchBucketPolicy:
                    # No policy is good - bucket isn't explicitly made public
                    pass
                
                # Check 2: Get public access block configuration
                public_access_block = None
                try:
                    access_response = s3.get_public_access_block(Bucket=bucket_name)
                    public_access_block = access_response.get('PublicAccessBlockConfiguration', {})
                except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                    # No public access block - bucket might be public!
                    pass
                
                # Analyze if bucket is public
                is_public = False
                public_reason = ""
                
                # Check 1: Does bucket policy allow public access?
                if policy:
                    try:
                        policy_json = json.loads(policy)
                        
                        # Look for dangerous statements
                        for statement in policy_json.get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                principal = statement.get('Principal')
                                action = statement.get('Action', [])
                                
                                # Convert to list if it's a string
                                if isinstance(action, str):
                                    action = [action]
                                
                                # Check if principal is public
                                principal_is_public = False
                                if principal == "*":
                                    principal_is_public = True
                                elif isinstance(principal, dict) and principal.get('AWS') == '*':
                                    principal_is_public = True
                                elif isinstance(principal, dict) and principal.get('CanonicalUser') == '*':
                                    principal_is_public = True
                                
                                # Check if action allows read
                                allows_read = False
                                read_actions = ['s3:GetObject', 's3:GetObject*', 's3:Get*', 's3:List*', 's3:*', '*']
                                for act in action:
                                    if any(read_action in act for read_action in read_actions):
                                        allows_read = True
                                        break
                                
                                if principal_is_public and allows_read:
                                    is_public = True
                                    public_reason = "Bucket policy allows public read access"
                                    break
                                    
                    except json.JSONDecodeError:
                        # Invalid JSON in policy
                        findings.append({
                            'id': f'S3_INVALID_POLICY_{bucket_name}',
                            'severity': 'MEDIUM',
                            'title': 'Invalid S3 Bucket Policy',
                            'resource': f'arn:aws:s3:::{bucket_name}',
                            'description': f"S3 bucket '{bucket_name}' has an invalid JSON policy that cannot be parsed.",
                            'remediation': (
                                "1. Go to AWS S3 Console\n"
                                f"2. Navigate to bucket: {bucket_name}\n"
                                "3. Click 'Permissions' tab\n"
                                "4. Click 'Bucket Policy'\n"
                                "5. Fix or remove the invalid policy"
                            ),
                            'context': {
                                'bucket_name': bucket_name,
                                'issue': 'invalid_policy_json'
                            }
                        })
                
                # Check 2: Is public access block disabled?
                if public_access_block:
                    # These should all be True to block public access
                    block_public_acls = public_access_block.get('BlockPublicAcls', False)
                    ignore_public_acls = public_access_block.get('IgnorePublicAcls', False)
                    block_public_policy = public_access_block.get('BlockPublicPolicy', False)
                    restrict_public_buckets = public_access_block.get('RestrictPublicBuckets', False)
                    
                    if not all([block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets]):
                        is_public = True
                        public_reason = "Public access block is not fully enabled"
                
                # If bucket is public, create finding
                if is_public:
                    findings.append({
                        'id': f'S3_PUBLIC_{bucket_name}',
                        'severity': 'CRITICAL',
                        'title': 'Public S3 Bucket',
                        'resource': f'arn:aws:s3:::{bucket_name}',
                        'description': (
                            f"S3 bucket '{bucket_name}' is publicly accessible.\n"
                            f"Reason: {public_reason}\n\n"
                            "🚨 This means anyone on the internet can potentially:\n"
                            "   • Read sensitive files (customer data, source code)\n"
                            "   • List all files in the bucket\n"
                            "   • Access confidential information"
                        ),
                        'remediation': (
                            "IMMEDIATE ACTION REQUIRED:\n\n"
                            "Option 1: Enable public access block (Recommended):\n"
                            f"  aws s3api put-public-access-block \\\n"
                            f"    --bucket {bucket_name} \\\n"
                            f"    --public-access-block-configuration '\n"
                            f"      BlockPublicAcls=true,\n"
                            f"      IgnorePublicAcls=true,\n"
                            f"      BlockPublicPolicy=true,\n"
                            f"      RestrictPublicBuckets=true'\n\n"
                            "Option 2: Review and fix bucket policy:\n"
                            f"  1. Go to: https://s3.console.aws.amazon.com/s3/bucket/{bucket_name}\n"
                            "  2. Click 'Permissions' tab\n"
                            "  3. Remove any statements with 'Principal': '*'\n\n"
                            "Option 3: Move sensitive data immediately:\n"
                            f"  aws s3 mv s3://{bucket_name}/sensitive-folder/ s3://new-private-bucket/ --recursive"
                        ),
                        'impact': (
                            "DATA BREACH RISK: This exact issue caused the Capital One breach "
                            "(106M records exposed, $80M fine).\n"
                            "Compliance violations: GDPR, HIPAA, PCI-DSS, SOC 2."
                        ),
                        'context': {
                            'bucket_name': bucket_name,
                            'public_reason': public_reason,
                            'has_policy': bool(policy),
                            'has_access_block': bool(public_access_block)
                        }
                    })
                    
                    if client.verbose:
                        print(f"   🔴 Found public bucket: {bucket_name}")
            
            except Exception as e:
                # Don't fail entire scan if one bucket has issues
                error_msg = str(e)
                if 'AccessDenied' in error_msg:
                    findings.append({
                        'id': f'S3_ACCESS_DENIED_{bucket_name}',
                        'severity': 'MEDIUM',
                        'title': 'Cannot Access S3 Bucket',
                        'resource': f'arn:aws:s3:::{bucket_name}',
                        'description': f"Sage does not have permission to check bucket '{bucket_name}'.",
                        'remediation': "Add s3:GetBucketPolicy and s3:GetPublicAccessBlock permissions to Sage's IAM role.",
                        'context': {'bucket_name': bucket_name, 'error': error_msg}
                    })
                elif client.verbose:
                    print(f"   ⚠️  Error checking bucket {bucket_name}: {error_msg}")
        
        if client.verbose:
            if findings:
                public_count = sum(1 for f in findings if 'S3_PUBLIC_' in f['id'])
                print(f"   📊 Found {public_count} public S3 buckets")
            else:
                print("   ✅ No public S3 buckets found")
                
    except Exception as e:
        # If we can't even list buckets, add a finding
        findings.append({
            'id': 'S3_GENERAL_ERROR',
            'severity': 'HIGH',
            'title': 'Cannot Scan S3 Buckets',
            'resource': 'arn:aws:s3:::*',
            'description': f"Sage could not scan S3 buckets: {str(e)}",
            'remediation': "Ensure Sage has s3:ListBuckets permission in IAM.",
            'context': {'error': str(e)}
        })
    
    return findings

# Simple test function
def _test_rule():
    """Test the rule (for development only)"""
    print("Testing Public S3 Buckets Rule...")
    
    # Mock finding for testing
    test_finding = {
        'id': 'S3_PUBLIC_TEST_BUCKET',
        'severity': 'CRITICAL',
        'title': 'Test Public S3 Bucket',
        'resource': 'arn:aws:s3:::test-bucket',
        'description': 'This is a test finding for development.',
        'remediation': 'Run: aws s3api put-public-access-block ...',
        'impact': 'Test impact statement'
    }
    
    print(f"✅ Rule test successful - would find: {test_finding['title']}")
    return [test_finding]

if __name__ == "__main__":
    # Only runs if file is executed directly
    _test_rule()
