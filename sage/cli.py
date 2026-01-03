#!/usr/bin/env python3
"""
Sage CLI - Command Line Interface
Entry point for the Sage AWS Security Scanner.
"""

import argparse
import sys
import os
from .scanner import scan_account, print_summary
from .output.console import display_findings  # We'll create this in File 7

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

def main():
    """Main entry point for Sage CLI"""
    parser = argparse.ArgumentParser(
        description="Sage: AWS Security Scanner - Find the 5 misconfigurations that cause breaches",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sage scan                           # Scan default AWS profile
  sage scan --profile production      # Scan specific AWS profile
  sage --help                         # Show this help message
  sage version                        # Show Sage version

What Sage Finds (v1.0):
  🔴 Public S3 buckets (Capital One breach)
  🔴 Admin users without MFA (coming soon)
  ⚠️  Wildcard policies (coming soon)
  ⚠️  Open SSH/RDP ports (coming soon)
  🟡 Old access keys (coming soon)
        """
    )
    
    # Main command
    parser.add_argument(
        "command",
        nargs="?",  # Makes it optional
        choices=["scan", "configure", "version"],
        help="Command to run: scan, configure, or version"
    )
    
    # Optional arguments for scan command
    parser.add_argument(
        "--profile",
        help="AWS CLI profile name (default: default)",
        default="default"
    )
    
    parser.add_argument(
        "--format",
        choices=["console", "json", "csv"],
        default="console",
        help="Output format (default: console)"
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
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Minimal output, just findings"
    )
    
    args = parser.parse_args()
    
    # If no command provided, show help
    if not args.command:
        if not args.quiet:
            print_banner()
        parser.print_help()
        return 0
    
    # Handle commands
    if args.command == "version":
        from . import __version__, __author__
        print(f"Sage v{__version__}")
        print(f"Created by {__author__}")
        return 0
        
    elif args.command == "configure":
        if not args.quiet:
            print("🔐 AWS Configuration Helper")
            print("=" * 50)
        print("\nSage uses your existing AWS CLI configuration.")
        print("\nTo set up AWS credentials:")
        print("\nOption 1: Use AWS CLI (recommended)")
        print("  aws configure")
        print("  # or for a specific profile:")
        print("  aws configure --profile production")
        
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
        if not args.quiet:
            print_banner()
            print(f"\n🔍 Starting Sage security scan...")
            print(f"   Profile: {args.profile}")
            print(f"   Region:  {args.region}")
            print(f"   Format:  {args.format}")
            
            if args.verbose:
                print(f"   Verbose: Enabled")
            
            if args.output:
                print(f"   Output:  {args.output}")
            
            print("\n" + "="*60)
        
        try:
            # Run the actual scan!
            findings = scan_account(
                profile=args.profile,
                region=args.region,
                verbose=args.verbose
            )
            
            # Remove metadata finding for display
            display_findings = [f for f in findings if f['id'] != 'SCAN_METADATA']
            metadata = next((f for f in findings if f['id'] == 'SCAN_METADATA'), None)
            
            # Output based on format
            if args.format == "console":
                # Display findings in console
                if display_findings:
                    print("\n🔍 SECURITY FINDINGS")
                    print("="*60)
                    
                    # Group by severity
                    critical = [f for f in display_findings if f['severity'] == 'CRITICAL']
                    high = [f for f in display_findings if f['severity'] == 'HIGH']
                    medium = [f for f in display_findings if f['severity'] == 'MEDIUM']
                    low = [f for f in display_findings if f['severity'] == 'LOW']
                    info = [f for f in display_findings if f['severity'] == 'INFO']
                    
                    # Display critical first (most important)
                    if critical:
                        print("\n🔴 CRITICAL - Immediate Action Required")
                        print("-"*40)
                        for i, finding in enumerate(critical, 1):
                            print(f"\n{i}. {finding['title']}")
                            print(f"   Resource: {finding['resource']}")
                            print(f"   {finding['description']}")
                            if 'remediation' in finding:
                                print(f"\n   🔧 FIX:")
                                print(f"   {finding['remediation']}")
                            print()
                    
                    # Then high
                    if high:
                        print("\n🟠 HIGH - Fix Within 24 Hours")
                        print("-"*40)
                        for i, finding in enumerate(high, 1):
                            print(f"\n{i}. {finding['title']}")
                            print(f"   Resource: {finding['resource']}")
                            print(f"   {finding['description'][:200]}...")
                            print()
                    
                    # Show counts for others
                    if medium:
                        print(f"\n🟡 MEDIUM Issues: {len(medium)} (fix within 7 days)")
                    if low:
                        print(f"🔵 LOW Issues: {len(low)} (consider fixing)")
                    if info and args.verbose:
                        for finding in info:
                            print(f"\nℹ️  {finding['title']}")
                            print(f"   {finding['description']}")
                
                # Print summary
                if metadata:
                    print("\n" + "="*60)
                    print("📊 SCAN SUMMARY")
                    print("="*60)
                    meta = metadata.get('metadata', {})
                    print(f"Account: {meta.get('account_id', 'Unknown')}")
                    if meta.get('account_alias'):
                        print(f"Alias:   {meta['account_alias']}")
                    print("-"*60)
                    
                    crit_count = sum(1 for f in display_findings if f['severity'] == 'CRITICAL')
                    high_count = sum(1 for f in display_findings if f['severity'] == 'HIGH')
                    med_count = sum(1 for f in display_findings if f['severity'] == 'MEDIUM')
                    
                    if crit_count > 0:
                        print(f"🔴 CRITICAL: {crit_count}  - DROP EVERYTHING AND FIX!")
                    if high_count > 0:
                        print(f"🟠 HIGH:     {high_count}")
                    if med_count > 0:
                        print(f"🟡 MEDIUM:   {med_count}")
                    
                    if crit_count == 0 and high_count == 0 and med_count == 0:
                        print("✅ No security issues found!")
                    
                    print("="*60)
                
                # Exit code based on findings
                crit_count = sum(1 for f in display_findings if f['severity'] == 'CRITICAL')
                if crit_count > 0:
                    print(f"\n❌ Found {crit_count} CRITICAL issues. Exit code: 1")
                    return 1
                else:
                    print(f"\n✅ Scan complete. Exit code: 0")
                    return 0
                    
            elif args.format == "json":
                # Simple JSON output (we'll improve in File 8)
                import json
                output_data = {
                    "scan": {
                        "profile": args.profile,
                        "region": args.region
                    },
                    "findings": display_findings,
                    "summary": metadata.get('metadata', {}) if metadata else {}
                }
                
                if args.output:
                    with open(args.output, 'w') as f:
                        json.dump(output_data, f, indent=2, default=str)
                    print(f"✅ JSON report saved to: {args.output}")
                else:
                    print(json.dumps(output_data, indent=2, default=str))
                    
            elif args.format == "csv":
                # Simple CSV output (we'll improve in File 9)
                import csv
                
                if args.output:
                    with open(args.output, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Severity', 'Title', 'Resource', 'Description'])
                        for finding in display_findings:
                            writer.writerow([
                                finding['severity'],
                                finding['title'],
                                finding['resource'],
                                finding['description'][:100]  # First 100 chars
                            ])
                    print(f"✅ CSV report saved to: {args.output}")
                else:
                    # Print to console
                    print("Severity,Title,Resource,Description")
                    for finding in display_findings:
                        print(f"{finding['severity']},{finding['title']},{finding['resource']},{finding['description'][:100]}")
            
            return 0
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Scan interrupted by user")
            return 130  # Standard interrupt exit code
            
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
