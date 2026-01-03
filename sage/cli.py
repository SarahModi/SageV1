#!/usr/bin/env python3
"""
Sage CLI - Command Line Interface
Entry point for the Sage AWS Security Scanner.
"""

import argparse
import sys
import os

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

What Sage Finds:
  🔴 Public S3 buckets (Capital One breach)
  🔴 Admin users without MFA
  ⚠️  Wildcard policies that could delete everything
  ⚠️  Open SSH/RDP ports to internet
  🟡 Old access keys (>90 days)
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
        print_banner()
        print(f"\n🔍 Starting Sage security scan...")
        print(f"   Profile: {args.profile}")
        print(f"   Region:  {args.region}")
        print(f"   Format:  {args.format}")
        
        if args.verbose:
            print(f"   Verbose: Enabled")
        
        print("\n⏳ Scanning AWS account...")
        print("   (Scanner logic will be implemented in File 3)")
        
        # Placeholder for actual scan
        print("\n✅ Scan complete!")
        print("\n📊 Summary:")
        print("   Critical findings: 0 (scanner not implemented yet)")
        print("   High findings:     0")
        print("   Medium findings:   0")
        print("   Passed checks:     0")
        
        print("\n💡 Next: Run 'sage configure' if you haven't set up AWS credentials")
        return 0
    
    else:
        print(f"❌ Unknown command: {args.command}")
        parser.print_help()
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)
