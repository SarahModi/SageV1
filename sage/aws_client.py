"""
AWS Client for Sage
Safe, rate-limited AWS API client to prevent throttling.
"""

import boto3
import botocore
import time
from botocore.exceptions import ClientError, NoCredentialsError, NoRegionError
from typing import Optional, Dict, Any
import sys

class RateLimiter:
    """
    Simple token bucket rate limiter to avoid AWS API throttling.
    Sage will be polite and not hammer AWS APIs.
    """
    
    def __init__(self, requests_per_second: int = 5):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_second: Maximum API calls per second (default: 5)
        """
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_call_time = 0
        
    def wait(self):
        """Wait if needed to maintain rate limit"""
        now = time.time()
        time_since_last = now - self.last_call_time
        
        if time_since_last < self.min_interval:
            # Wait the remaining time
            sleep_time = self.min_interval - time_since_last
            time.sleep(sleep_time)
            
        self.last_call_time = time.time()

class AWSClient:
    """
    Safe AWS API client with rate limiting and error handling.
    This is the core connection to AWS for Sage.
    """
    
    def __init__(self, profile: str = "default", region: str = "us-east-1", verbose: bool = False):
        """
        Initialize AWS client.
        
        Args:
            profile: AWS CLI profile name
            region: AWS region
            verbose: Enable verbose output
        """
        self.profile = profile
        self.region = region
        self.verbose = verbose
        self.rate_limiter = RateLimiter(requests_per_second=5)
        
        # Will be set during initialization
        self.session = None
        self.account_id = None
        self.account_alias = None
        
        # Initialize the session
        self._initialize_session()
    
    def _initialize_session(self):
        """Initialize boto3 session and validate credentials"""
        try:
            if self.verbose:
                print(f"   🔗 Connecting to AWS with profile: '{self.profile}'")
            
            # Create session with specified profile
            self.session = boto3.Session(
                profile_name=self.profile,
                region_name=self.region
            )
            
            # Test connection by getting caller identity
            sts_client = self.session.client('sts')
            self.rate_limiter.wait()
            
            identity = sts_client.get_caller_identity()
            self.account_id = identity['Account']
            self.user_arn = identity['Arn']
            
            # Try to get account alias
            try:
                iam_client = self.session.client('iam')
                self.rate_limiter.wait()
                response = iam_client.list_account_aliases()
                if response['AccountAliases']:
                    self.account_alias = response['AccountAliases'][0]
            except ClientError:
                # Not all accounts have aliases, that's OK
                self.account_alias = None
            
            if self.verbose:
                print(f"   ✅ Connected to AWS Account ID: {self.account_id}")
                if self.account_alias:
                    print(f"   📛 Account Alias: {self.account_alias}")
                print(f"   👤 User: {self.user_arn}")
                print(f"   🌍 Region: {self.region}")
                
        except NoCredentialsError:
            error_msg = (
                "\n❌ AWS credentials not found.\n\n"
                "Sage needs AWS credentials to scan your account.\n\n"
                "Setup options:\n"
                "1. Run: sage configure          # Shows setup instructions\n"
                "2. Set environment variables:   AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY\n"
                "3. Use AWS CLI:                 aws configure\n"
                "4. Use --profile flag:          sage scan --profile your-profile\n\n"
                "📚 Documentation: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html"
            )
            raise Exception(error_msg)
            
        except NoRegionError:
            error_msg = (
                "\n❌ AWS region not configured.\n\n"
                "Please specify a region:\n"
                "1. Use --region flag:           sage scan --region us-east-1\n"
                "2. Set environment variable:    export AWS_DEFAULT_REGION='us-east-1'\n"
                "3. Configure AWS CLI:           aws configure set region us-east-1"
            )
            raise Exception(error_msg)
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidClientTokenId':
                raise Exception(f"❌ Invalid AWS credentials for profile '{self.profile}'")
            elif error_code == 'AccessDenied':
                raise Exception(f"❌ Access denied. User '{self.user_arn}' needs sts:GetCallerIdentity permission")
            else:
                raise Exception(f"❌ AWS API error: {str(e)}")
    
    def get_client(self, service_name: str):
        """
        Get a rate-limited boto3 client for the specified service.
        
        Args:
            service_name: AWS service name (e.g., 's3', 'iam', 'ec2')
            
        Returns:
            boto3 client with rate limiting
        """
        if not self.session:
            raise Exception("AWS session not initialized")
        
        # Create the client
        client = self.session.client(service_name)
        
        # Store original _make_request method
        original_make_request = client._make_request
        
        # Create wrapped method with rate limiting - FIXED SIGNATURE
        def rate_limited_make_request(*args, **kwargs):
            self.rate_limiter.wait()
            return original_make_request(*args, **kwargs)
        
        # Replace the method
        client._make_request = rate_limited_make_request
        
        return client
    
    def test_connection(self) -> Dict[str, Any]:
        """
        Test AWS connection and return account info.
        Used for the initial connection check in scans.
        """
        return {
            'account_id': self.account_id,
            'account_alias': self.account_alias,
            'user_arn': self.user_arn,
            'region': self.region,
            'profile': self.profile
        }
    
    def safe_api_call(self, service: str, method: str, **kwargs):
        """
        Make a safe API call with error handling.
        
        Args:
            service: AWS service name
            method: Method to call on the client
            **kwargs: Arguments to pass to the method
            
        Returns:
            API response or None if error
        """
        try:
            client = self.get_client(service)
            
            # Get the method from client
            api_method = getattr(client, method)
            
            # Make the call
            return api_method(**kwargs)
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            # Don't crash on expected errors
            expected_errors = [
                'NoSuchBucketPolicy',  # Bucket has no policy
                'NoSuchEntity',        # IAM entity doesn't exist
                'AccessDenied',        # Permission issue (we'll log it)
            ]
            
            if error_code in expected_errors:
                if self.verbose:
                    print(f"   ⚠️  Expected error ({error_code}) for {service}.{method}")
                return None
            else:
                # Re-raise unexpected errors
                raise
    
    def get_simple_s3_info(self):
        """
        Simple S3 test - list buckets (first API call example).
        Will be expanded in File 4.
        """
        try:
            s3 = self.get_client('s3')
            response = s3.list_buckets()
            
            bucket_count = len(response.get('Buckets', []))
            
            if self.verbose:
                print(f"   📦 Found {bucket_count} S3 buckets")
                
            return {
                'bucket_count': bucket_count,
                'buckets': [b['Name'] for b in response.get('Buckets', [])][:5]  # First 5 only
            }
            
        except ClientError as e:
            if self.verbose:
                print(f"   ⚠️  Could not list S3 buckets: {e.response['Error']['Code']}")
            return {'bucket_count': 0, 'buckets': []}

# Quick test function (not used in production)
def _test_client():
    """Test the AWS client (for development only)"""
    print("Testing AWS Client...")
    try:
        client = AWSClient(verbose=True)
        print(f"✅ Client initialized for account: {client.account_id}")
        
        # Test S3 connection
        s3_info = client.get_simple_s3_info()
        print(f"✅ S3 test successful: {s3_info['bucket_count']} buckets")
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")

if __name__ == "__main__":
    # Only runs if file is executed directly (for testing)
    _test_client()
