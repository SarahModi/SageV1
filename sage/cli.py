#!/usr/bin/env python3
"""
Sage CLI - Command Line Interface
Entry point for the Sage AWS Security Scanner.
"""

import argparse
import sys
import os
import json
import csv
from datetime import datetime

def print_banner():
    """Print Sage banner"""
    banner = """
╔══════════════════════════════════════════════╗
║                SAGE v1.0                     ║
║     AWS Security Scanner                     ║
║     Find the 5 misconfigurations             ║
║     that actually cause breaches.            ║
║                                              ║
║     By: Sarah Modi (18-year-old founder)     ║
║     https://github.com/SarahModi/sagev1      ║
╚══════════════════════════════════════════════╝
"""
    print(banner)

def display_findings_console(findings, verbose=False):
    """Display findings in console with formatting"""
    
    # Filter out metadata
    display_findings = [f for f in findings if f['id'] not in ['SCAN_METADATA', 'SCAN_SUMMARY_NO_CRITICAL']]
    metadata = next((f for f in findings if f['id'] == 'SCAN_METADATA'), None)
    
    if not display_findings:
        print("\n✅ No security issues found!")
        if metadata and 'metadata' in metadata:
            print(f"   Account: {metadata['metadata'].get('account_id', 'Unknown')}")
        return
    
    # Group by severity
    critical = [f for f in display_findings if f['severity'] == 'CRITICAL']
    high = [f for f in display_findings if f['severity'] == 'HIGH']
    medium = [f for f in display_findings if f['severity'] == 'MEDIUM']
    low = [f for f in display_findings if f['severity'] == 'LOW']
    info = [f for f in display_findings if f['severity'] == 'INFO']
    
    print(f"\n📊 Found {len(display_findings)} security issues:")
    print(f"   🔴 CRITICAL: {len(critical)}")
    print(f"   🟠 HIGH:     {len(high)}")
    print(f"   🟡 MEDIUM:   {len(medium)}")
    print(f"   🔵 LOW:      {len(low)}")
    print(f"   ℹ️  INFO:     {len(info)}")
    
    # Show critical findings first
    if critical:
        print("\n" + "="*60)
        print("🔴 CRITICAL FINDINGS - IMMEDIATE ACTION REQUIRED")
        print("="*60)
        
        for i, finding in enumerate(critical, 1):
            print(f"\n{i}. {finding['title']}")
            print(f"   📍 Resource: {finding['resource']}")
            print(f"   📝 {finding['description']}")
            
            if 'remediation' in finding and finding['remediation']:
                print(f"\n   🔧 HOW TO FIX:")
                fix_lines = finding['remediation'].split('\n')
                for line in fix_lines[:5]:  # Show first 5 lines
                    if line.strip():
                        print(f"      {line}")
                if len(fix_lines) > 5:
                    print(f"      ... (see full report for complete fix)")
            
            if verbose and 'impact' in finding:
                print(f"\n   ⚠️  IMPACT: {finding['impact'][:200]}...")
    
    # Show high findings
    if high:
        print("\n" + "="*60)
        print("🟠 HIGH FINDINGS - FIX WITHIN 24 HOURS")
        print("="*60)
        
        for i, finding in enumerate(high, 1):
            print(f"\n{i}. {finding['title']}")
            print(f"   📍 {finding['resource']}")
            print(f"   📝 {finding['description'][:150]}...")
    
    # Summary
    if metadata and 'metadata' in metadata:
        print("\n" + "="*60)
        print("📈 SCAN SUMMARY")
        print("="*60)
        meta = metadata['metadata']
        print(f"Account ID:  {meta.get('account_id', 'Unknown')}")
        if meta.get('account_alias'):
            print(f"Account Alias: {meta['account_alias']}")
        print(f"Scan Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-"*60)

def main():
    """Main entry point for Sage CLI"""
    parser = argparse.ArgumentParser(
        description="Sage: AWS Security Scanner - Find the 5 misconfigurations that cause breaches",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sage scan                           # Scan default AWS profile
  sage scan --profile production      # Scan specific AWS profile
  sage scan --verbose                 # Detailed output
  sage scan --format json             # JSON output for CI/CD
  sage --help                         # Show help
  sage version                        # Show version

The 5 checks:
  1. 🔴 Public S3 buckets (Capital One breach)
  2. 🔴 Admin users without MFA
  3. ⚠️  Wildcard policies
  4. 🚪 Open SSH/RDP ports  
  5. 🔑 Old access keys (>90 days)
        """
    )
    
    # Main command
    parser.add_argument(
        "command",
        nargs="?",  # Makes it optional
        choices=["scan", "configure", "version"],
        help="Command to run: scan, configure, or version"
    )
    
    # Optional arguments
    parser.add_argument(
        "--profile",
        help="AWS CLI profile name (default: default)",
        default="default"
    )
    
    parser.add_argument(
        "--format",
        choices=["console", "json", "csv"],
        default="console",
        help="Output format"
    )
    
    parser.add_argument(
        "--output",
        help="Output file path (for json/csv formats)",
        default=None
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed debugging information"
    )
    
    parser.add_argument(
        "--region",
        help="AWS region (default: us-east-1)",
        default="us-east-1"
    )
    
    args = parser.parse_args()
    
    # If no command provided, show help
    if not args.command:
        print_banner()
        parser.print_help()
        return 0
    
    # Handle commands
    if args.command == "version":
        from sage import __version__, __author__
        print(f"Sage v{__version__}")
        print(f"Created by {__author__}")
        return 0
        
    elif args.command == "configure":
        print("🔐 AWS Configuration Helper")
        print("=" * 50)
        print("\nSage uses your existing AWS CLI configuration.")
        print("\nTo set up AWS credentials:")
        print("\nOption 1: Use AWS CLI (recommended)")
        print("  aws configure")
        print("  # or for a specific profile:")
        print("  aws configure --profile your-profile")
        
        print("\nOption 2: Environment variables")
        print("  export AWS_ACCESS_KEY_ID='your-access-key'")
        print("  export AWS_SECRET_ACCESS_KEY='your-secret-key'")
        print("  export AWS_DEFAULT_REGION='us-east-1'")
        
        print("\nOption 3: EC2 Instance Profile")
        print("  Sage will automatically use IAM roles on EC2 instances")
        
        print("\n📚 Need help? See AWS documentation:")
        print("  https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html")
        return 0
        
    elif args.command == "scan":
        if not args.verbose:
            print_banner()
        
        print(f"\n🔍 Starting Sage security scan...")
        print(f"   Profile: {args.profile}")
        print(f"   Region:  {args.region}")
        print(f"   Format:  {args.format}")
        
        if args.verbose:
            print(f"   Verbose: Enabled")
        
        if args.output:
            print(f"   Output:  {args.output}")
        
        print()
        
        try:
            # Import and run scanner
            from sage.scanner import scan_account
            
            # Run the scan!
            findings = scan_account(
                profile=args.profile,
                region=args.region,
                verbose=args.verbose
            )
            
            # Output based on format
            if args.format == "console":
                display_findings_console(findings, args.verbose)
                
                # Exit code based on critical findings
                critical_count = sum(1 for f in findings 
                                   if f['severity'] == 'CRITICAL' 
                                   and f['id'] not in ['SCAN_METADATA', 'SCAN_SUMMARY_NO_CRITICAL'])
                
                if critical_count > 0:
                    print(f"\n❌ Found {critical_count} CRITICAL issues. Exit code: 1")
                    return 1
                else:
                    print(f"\n✅ Scan complete. Exit code: 0")
                    return 0
                    
            elif args.format == "json":
                # Prepare JSON output
                output_data = {
                    "scan": {
                        "timestamp": datetime.now().isoformat(),
                        "profile": args.profile,
                        "region": args.region
                    },
                    "findings": [f for f in findings if f['id'] not in ['SCAN_METADATA']],
                    "summary": {
                        "total": len(findings) - 1,  # exclude metadata
                        "critical": sum(1 for f in findings if f['severity'] == 'CRITICAL'),
                        "high": sum(1 for f in findings if f['severity'] == 'HIGH'),
                        "medium": sum(1 for f in findings if f['severity'] == 'MEDIUM'),
                        "low": sum(1 for f in findings if f['severity'] == 'LOW')
                    }
                }
                
                if args.output:
                    with open(args.output, 'w') as f:
                        json.dump(output_data, f, indent=2, default=str)
                    print(f"✅ JSON report saved to: {args.output}")
                else:
                    print(json.dumps(output_data, indent=2, default=str))
                    
            elif args.format == "csv":
                # Prepare CSV output
                display_findings = [f for f in findings if f['id'] not in ['SCAN_METADATA']]
                
                if args.output:
                    with open(args.output, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Severity', 'Title', 'Resource', 'Description', 'Remediation'])
                        for finding in display_findings:
                            writer.writerow([
                                finding['severity'],
                                finding['title'],
                                finding['resource'],
                                finding['description'][:500],
                                finding.get('remediation', '')[:500] if 'remediation' in finding else ''
                            ])
                    print(f"✅ CSV report saved to: {args.output}")
                else:
                    # Print to console
                    writer = csv.writer(sys.stdout)
                    writer.writerow(['Severity', 'Title', 'Resource', 'Description'])
                    for finding in display_findings:
                        writer.writerow([
                            finding['severity'],
                            finding['title'],
                            finding['resource'],
                            finding['description'][:200]
                        ])
            
            return 0
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Scan interrupted by user")
            return 130
            
        except Exception as e:
            print(f"\n❌ Scan failed: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1
    
    else:
        print(f"❌ Unknown command: {args.command}")
        parser.print_help()
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        sys.exit(1)
