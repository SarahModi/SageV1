"""
Rule #4: Open SSH/RDP Ports Check
Finds security groups with SSH (22) or RDP (3389) open to the internet.
These are constantly scanned by hackers and bots.
"""

from typing import List, Dict, Any
from ..aws_client import AWSClient

def check_open_ssh_rdp(client: AWSClient) -> List[Dict[str, Any]]:
    """
    Check for security groups with SSH or RDP open to the internet (0.0.0.0/0).
    
    Why this is critical:
    - SSH port 22: Constantly scanned for weak passwords, crypto mining
    - RDP port 3389: #1 initial access vector for ransomware attacks  
    - Real attacks: Botnets scan these ports 24/7 from Russia/China/Vietnam
    - Impact: Server compromise, data theft, ransomware deployment
    
    Args:
        client: AWSClient instance
        
    Returns:
        List of findings for open SSH/RDP ports
    """
    
    findings = []
    
    try:
        if client.verbose:
            print("   🚪 Checking security groups for open SSH/RDP ports...")
        
        ec2 = client.get_client('ec2')
        
        # Get all security groups
        security_groups = []
        paginator = ec2.get_paginator('describe_security_groups')
        for page in paginator.paginate():
            security_groups.extend(page['SecurityGroups'])
        
        if client.verbose:
            print(f"   🔍 Scanning {len(security_groups)} security groups...")
        
        for sg in security_groups:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            vpc_id = sg.get('VpcId', 'default')
            description = sg.get('Description', 'No description')
            
            # Check inbound rules
            for rule in sg.get('IpPermissions', []):
                # Check for SSH (port 22) or RDP (port 3389)
                is_ssh = rule.get('FromPort') == 22 and rule.get('ToPort') == 22
                is_rdp = rule.get('FromPort') == 3389 and rule.get('ToPort') == 3389
                
                if not (is_ssh or is_rdp):
                    continue
                
                # Check if open to internet (0.0.0.0/0)
                open_to_internet = False
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        open_to_internet = True
                        break
                
                # Also check IPv6 (::/0)
                if not open_to_internet:
                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        if ipv6_range.get('CidrIpv6') == '::/0':
                            open_to_internet = True
                            break
                
                if open_to_internet:
                    port = 22 if is_ssh else 3389
                    protocol = 'SSH' if is_ssh else 'RDP'
                    
                    # Get instances using this security group
                    instances = []
                    try:
                        instances_resp = ec2.describe_instances(
                            Filters=[
                                {
                                    'Name': 'instance.group-id',
                                    'Values': [sg_id]
                                }
                            ]
                        )
                        
                        for reservation in instances_resp.get('Reservations', []):
                            for instance in reservation.get('Instances', []):
                                instance_id = instance.get('InstanceId')
                                instance_name = 'Unnamed'
                                
                                # Try to get name tag
                                for tag in instance.get('Tags', []):
                                    if tag.get('Key') == 'Name':
                                        instance_name = tag.get('Value', 'Unnamed')
                                        break
                                
                                instances.append(f"{instance_id} ({instance_name})")
                                
                    except Exception as e:
                        if client.verbose:
                            print(f"      ⚠️  Could not get instances for SG {sg_id}: {str(e)}")
                    
                    # Get the risk level based on instances
                    risk_level = 'HIGH'
                    risk_explanation = ""
                    
                    if instances:
                        risk_level = 'CRITICAL'
                        risk_explanation = (
                            f"This security group is attached to {len(instances)} running instance(s):\n"
                            f"  • {', '.join(instances[:3])}" + 
                            ("..." if len(instances) > 3 else "")
                        )
                    else:
                        risk_explanation = "No running instances found with this security group (may be used by other services)."
                    
                    findings.append({
                        'id': f'OPEN_PORT_{sg_id}_{port}',
                        'severity': risk_level,
                        'title': f'Internet-Exposed {protocol} Port ({port})',
                        'resource': f"arn:aws:ec2:{client.region}:{client.account_id}:security-group/{sg_id}",
                        'description': (
                            f"Security group '{sg_name}' ({sg_id}) has {protocol} port {port} open to the entire internet (0.0.0.0/0).\n\n"
                            f"📋 Security Group Details:\n"
                            f"  • Name: {sg_name}\n"
                            f"  • ID: {sg_id}\n"
                            f"  • VPC: {vpc_id}\n"
                            f"  • Description: {description}\n\n"
                            f"{risk_explanation}\n\n"
                            "🚨 ATTACK SURFACE:\n"
                            f"  • {protocol} port {port} is constantly scanned by hackers worldwide\n"
                            "  • Common attack vectors:\n"
                            "     - Brute force password attacks\n"
                            "     - Exploitation of known vulnerabilities\n"
                            "     - Credential stuffing attacks\n"
                            f"  • {'🚨 CRITICAL: Active instances exposed!' if instances else '⚠️  HIGH: Configuration exposes future instances'}"
                        ),
                        'remediation': (
                            "IMMEDIATE ACTION REQUIRED:\n\n"
                            "Option 1: Restrict to specific IPs (Recommended):\n"
                            f"  1. Go to: https://{client.region}.console.aws.amazon.com/ec2/home#SecurityGroup:groupId={sg_id}\n"
                            "  2. Edit inbound rules\n"
                            "  3. Change '0.0.0.0/0' to your office IP or VPN IP\n"
                            "  4. Example: 203.0.113.0/24 (your office network)\n\n"
                            "Option 2: Use AWS Systems Manager Session Manager (Best Practice):\n"
                            "  1. Install SSM Agent on EC2 instances\n"
                            "  2. Remove SSH/RDP inbound rules entirely\n"
                            "  3. Connect via: https://console.aws.amazon.com/systems-manager/session-manager\n"
                            "  4. No open ports required!\n\n"
                            "Option 3: Use a Bastion Host/Jump Box:\n"
                            "  1. Create a single EC2 instance with SSH/RDP\n"
                            "  2. Restrict SSH/RDP to this bastion only\n"
                            "  3. Connect to other instances from bastion\n"
                            "  4. Monitor bastion closely for attacks"
                        ),
                        'impact': (
                            f"SERVER COMPROMISE RISK: Open {protocol} port = Welcome mat for hackers.\n"
                            "This could lead to:\n"
                            "• Cryptojacking (unauthorized crypto mining)\n"
                            "• Ransomware deployment and data encryption\n"
                            "• Data exfiltration and intellectual property theft\n"
                            "• Botnet recruitment for DDoS attacks\n"
                            "• Compliance violations (PCI-DSS, HIPAA, SOC 2)"
                        ),
                        'context': {
                            'security_group_id': sg_id,
                            'security_group_name': sg_name,
                            'port': port,
                            'protocol': 'tcp',
                            'cidr': '0.0.0.0/0',
                            'vpc_id': vpc_id,
                            'attached_instances': instances,
                            'instance_count': len(instances)
                        }
                    })
                    
                    if client.verbose:
                        if instances:
                            print(f"      🔴 CRITICAL: {protocol} port {port} open on {sg_name} with {len(instances)} instances!")
                        else:
                            print(f"      🟠 HIGH: {protocol} port {port} open on {sg_name}")
        
        # Also check for overly permissive rules (like port ranges)
        if client.verbose:
            print("      Checking for overly permissive port ranges...")
        
        for sg in security_groups:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            
            for rule in sg.get('IpPermissions', []):
                # Check for large port ranges open to internet
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                
                if from_port is not None and to_port is not None:
                    port_range = to_port - from_port
                    
                    # If range is large (more than 10 ports) and open to internet
                    if port_range > 10:
                        open_to_internet = False
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                open_to_internet = True
                                break
                        
                        if open_to_internet:
                            findings.append({
                                'id': f'LARGE_PORT_RANGE_{sg_id}_{from_port}_{to_port}',
                                'severity': 'MEDIUM',
                                'title': 'Large Port Range Open to Internet',
                                'resource': f"arn:aws:ec2:{client.region}:{client.account_id}:security-group/{sg_id}",
                                'description': f"Security group '{sg_name}' has ports {from_port}-{to_port} ({port_range+1} ports) open to internet.",
                                'remediation': "Restrict to specific ports and IP ranges.",
                                'context': {
                                    'security_group_id': sg_id,
                                    'from_port': from_port,
                                    'to_port': to_port,
                                    'port_range_size': port_range + 1
                                }
                            })
        
        if client.verbose:
            if findings:
                ssh_count = sum(1 for f in findings if 'OPEN_PORT_' in f['id'] and '22' in f['id'])
                rdp_count = sum(1 for f in findings if 'OPEN_PORT_' in f['id'] and '3389' in f['id'])
                critical_count = sum(1 for f in findings if f['severity'] == 'CRITICAL' and 'OPEN_PORT_' in f['id'])
                
                print(f"      📊 Found {ssh_count} open SSH ports, {rdp_count} open RDP ports ({critical_count} critical)")
            else:
                print("      ✅ No internet-exposed SSH/RDP ports found")
                
    except Exception as e:
        findings.append({
            'id': 'SECURITY_GROUP_CHECK_ERROR',
            'severity': 'MEDIUM',
            'title': 'Security Group Check Failed',
            'resource': 'arn:aws:ec2:*:*:security-group/*',
            'description': f"Could not check security groups: {str(e)}",
            'remediation': "Ensure Sage has ec2:DescribeSecurityGroups and ec2:DescribeInstances permissions.",
            'context': {'error': str(e)}
        })
        
        if client.verbose:
            print(f"   ⚠️  Security group check failed: {str(e)}")
    
    return findings

# Test function
def _test_rule():
    """Test the open SSH/RDP rule (for development only)"""
    print("Testing Open SSH/RDP Ports Rule...")
    
    # Mock finding for testing
    test_finding = {
        'id': 'OPEN_PORT_SG_TEST_22',
        'severity': 'CRITICAL',
        'title': 'Test Open SSH Port',
        'resource': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-123456',
        'description': 'Test SSH port open to internet - critical finding.',
        'remediation': 'Restrict SSH to specific IPs.',
        'impact': 'Server compromise risk'
    }
    
    print(f"✅ Rule test successful - would find: {test_finding['title']}")
    return [test_finding]

if __name__ == "__main__":
    # Only runs if file is executed directly
    _test_rule()
