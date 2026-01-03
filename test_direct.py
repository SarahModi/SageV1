#!/usr/bin/env python3
"""
Direct test of Sage scanner - bypasses CLI
"""

import sys
import os

# Add sage to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sage.scanner import scan_account

print("🧪 Testing Sage scanner DIRECTLY (bypassing CLI)...")
print("="*60)

try:
    # Run the actual scanner
    findings = scan_account(profile="sage-test", verbose=True)
    
    print(f"\n📊 Scanner returned {len(findings)} findings")
    
    if not findings:
        print("❌ No findings returned. Possible issues:")
        print("   1. AWS credentials not working")
        print("   2. Scanner error")
        print("   3. No issues in account (unlikely with test misconfigurations)")
        
        # Try to debug
        print("\n🔧 Debugging:")
        
        # Test AWS connection directly
        print("\n1. Testing AWS connection...")
        try:
            import boto3
            session = boto3.Session(profile_name="sage-test")
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            print(f"   ✅ Connected to AWS Account: {identity['Account']}")
            print(f"   👤 User: {identity['Arn']}")
        except Exception as e:
            print(f"   ❌ AWS connection failed: {str(e)}")
            print("\n💡 Try: aws configure --profile sage-test")
        
    else:
        print("\n🎉 FINDINGS FOUND!")
        print("="*60)
        
        for i, finding in enumerate(findings, 1):
            if finding['id'] == 'SCAN_METADATA':
                continue  # Skip metadata
            
            print(f"\n{i}. {finding['severity']}: {finding['title']}")
            print(f"   Resource: {finding['resource']}")
            print(f"   {finding['description'][:200]}...")
            
            if 'remediation' in finding:
                print(f"   Fix: {finding['remediation'].split('\\n')[0][:100]}...")
        
        # Show metadata if present
        metadata = next((f for f in findings if f['id'] == 'SCAN_METADATA'), None)
        if metadata and 'metadata' in metadata:
            meta = metadata['metadata']
            print(f"\n📈 Summary: {meta.get('critical_count', 0)} critical, "
                  f"{meta.get('high_count', 0)} high, "
                  f"{meta.get('medium_count', 0)} medium findings")
    
except Exception as e:
    print(f"\n❌ Scanner crashed: {str(e)}")
    import traceback
    traceback.print_exc()

print("\n" + "="*60)
