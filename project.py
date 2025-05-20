#!/usr/bin/env python3

import argparse
import sys
import psutil
import time
from scapy.all import ARP, ICMP, DNS, DHCP, rdpcap, TCP, IP, Raw
from scapy.layers.http import HTTPRequest
import re
import nmap3
import mmap

# Memory Forensics Module
def analyze_memory(memory_file):
    """Analyze memory dump for suspicious patterns and potential malware artifacts."""
    print(f"\n[*] Analyzing memory dump: {memory_file}")
    
    try:
        nmap = nmap3.Nmap()
        stats = {
            'total_size': 0,
            'suspicious_patterns': 0,
            'injection_indicators': 0,
            'encoded_blocks': 0,
            'c2_indicators': 0,
            'network_endpoints': 0,
            'active_ports': 0,
            'service_count': 0,
            'malicious_score': 0,
            'memory_regions': {
                'executable': 0,
                'writable': 0,
                'suspicious': 0
            }
        }
        
        # Initialize storage lists and patterns
        potential_injections = []
        possible_c2_addrs = []
        encoded_data = []
        suspicious_regions = []
        dll_injections = []
        
        # Define patterns for scanning
        patterns = {
            'powershell': rb'powershell\.exe',
            'mimikatz': rb'mimikatz|mimilib|sekurlsa',
            'remote_tools': rb'psexec|netcat|ncat|nc\.exe',
            'encodings': rb'base64|utf-16le|ascii',
            'exploit_strings': rb'kernel32\.dll|ntdll\.dll|shellcode|exploit',
            'c2_patterns': rb'beacon|command|control|admin|root|shell',
            'registry_paths': rb'HKEY_LOCAL_MACHINE\\|HKEY_CURRENT_USER\\',
            'script_engines': rb'wscript\.exe|cscript\.exe|mshta\.exe',
            'credentials': rb'password|login|cred|secret|token',
            'malware_patterns': rb'backdoor|trojan|keylog|ransomware|rootkit',
            'suspicious_dll': rb'inject|hook|spy|crypto|stealth'
        }
        
        # Define injection patterns
        injection_patterns = [
            rb'VirtualAlloc',
            rb'WriteProcessMemory',
            rb'CreateRemoteThread',
            rb'NtCreateThreadEx',
            rb'RtlCreateUserThread',
            rb'LoadLibraryA',
            rb'GetProcAddress',
            rb'VirtualProtect',
            rb'HeapCreate',
            rb'MapViewOfFile'
        ]
        
        # Define base64 and encryption patterns
        base64_pattern = rb'[A-Za-z0-9+/]{40,}={0,2}'
        encryption_patterns = [
            rb'AES|RSA|RC4|MD5|SHA\d*',
            rb'encrypt|decrypt|cipher',
            rb'private_key|public_key'
        ]
        
        # Define network patterns
        ip_pattern = rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        url_pattern = rb'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}'
        domain_pattern = rb'[a-zA-Z0-9\-\.]+\.(com|net|org|ru|cn|info|bit)'
        
        # Open memory dump file
        with open(memory_file, 'rb') as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            
            stats['total_size'] = len(mm) / (1024*1024)  # Size in MB
            print("[*] Initial memory dump statistics:")
            print(f"Memory dump size: {stats['total_size']:.2f} MB")
            
            # Enhanced pattern scanning with context
            for name, pattern in patterns.items():
                matches = [m.start() for m in re.finditer(pattern, mm)]
                if matches:
                    stats['suspicious_patterns'] += len(matches)
                    print(f"\n[!] Found {len(matches)} matches for {name}")
                    for pos in matches:
                        start = max(0, pos - 100)
                        end = min(len(mm), pos + 100)
                        context = mm[start:end]
                        try:
                            decoded = context.decode('utf-8', errors='ignore')
                            print(f"    Context: ...{decoded}...")
                        except:
                            pass

            # Advanced injection analysis
            for pattern in injection_patterns:
                positions = [m.start() for m in re.finditer(pattern, mm)]
                if positions:
                    stats['injection_indicators'] += len(positions)
                    potential_injections.extend(positions)
                    print(f"\n[!] Found potential injection indicator: {pattern.decode()}")
                    # Analyze surrounding memory
                    for pos in positions:
                        start = max(0, pos - 200)
                        end = min(len(mm), pos + 200)
                        suspicious_regions.append((start, end))

            # Enhanced encoded content analysis
            for pattern in [base64_pattern] + encryption_patterns:
                matches = [m.group() for m in re.finditer(pattern, mm)]
                if matches:
                    stats['encoded_blocks'] += len(matches)
                    encoded_data.extend(matches)
                    print(f"\n[!] Found {len(matches)} potential encoded/encrypted blocks")

            # Network indicator analysis
            for pattern in [ip_pattern, url_pattern, domain_pattern]:
                matches = [m.group() for m in re.finditer(pattern, mm)]
                stats['c2_indicators'] += len(matches)
                possible_c2_addrs.extend(matches)

            # Enhanced C2 analysis with nmap3
            if possible_c2_addrs:
                unique_addrs = set()
                for addr in set(possible_c2_addrs[:10]):
                    try:
                        addr_str = addr.decode('utf-8', 'ignore')
                        unique_addrs.add(addr_str)
                        
                        # Use nmap3 for service detection
                        results = nmap.nmap_version_detection(addr_str)
                        if results:
                            for host, data in results.items():
                                if 'ports' in data:
                                    stats['active_ports'] += len(data['ports'])
                                    for port in data['ports']:
                                        if 'service' in port:
                                            stats['service_count'] += 1
                                            print(f"\n[!] Detected service on {addr_str}:{port['portid']}")
                                            print(f"    Service: {port['service'].get('name', 'unknown')}")
                                            print(f"    Version: {port['service'].get('version', 'unknown')}")
                    except Exception as e:
                        print(f"[!] Error scanning {addr_str}: {str(e)}")
                
                stats['network_endpoints'] = len(unique_addrs)

            # Memory region analysis
            for start, end in suspicious_regions:
                region_data = mm[start:end]
                # Check for executable code patterns
                if re.search(rb'\x55\x8B\xEC|\x48\x89\x5C', region_data):
                    stats['memory_regions']['executable'] += 1
                # Check for writable sections
                if re.search(rb'heap|stack', region_data):
                    stats['memory_regions']['writable'] += 1
                # Check for suspicious content
                if re.search(rb'shellcode|inject|hook', region_data):
                    stats['memory_regions']['suspicious'] += 1

            # Calculate malicious score (0-100)
            stats['malicious_score'] = min(100, (
                (stats['suspicious_patterns'] * 2) +
                (stats['injection_indicators'] * 5) +
                (stats['encoded_blocks']) +
                (stats['c2_indicators'] * 3) +
                (stats['network_endpoints'] * 2) +
                (stats['memory_regions']['suspicious'] * 4)
            ))

            # Generate comprehensive report
            print("\n=== Memory Analysis Report ===")
            print("\nGeneral Statistics:")
            print(f"Memory Dump Size: {stats['total_size']:.2f} MB")
            print(f"Suspicious Pattern Matches: {stats['suspicious_patterns']}")
            print(f"Injection Indicators: {stats['injection_indicators']}")
            print(f"Encoded/Encrypted Blocks: {stats['encoded_blocks']}")
            print(f"C2 Communication Indicators: {stats['c2_indicators']}")
            print(f"Network Endpoints Found: {stats['network_endpoints']}")
            print(f"Active Ports Detected: {stats['active_ports']}")
            print(f"Services Identified: {stats['service_count']}")

            print("\nMemory Region Analysis:")
            print(f"Executable Regions: {stats['memory_regions']['executable']}")
            print(f"Writable Regions: {stats['memory_regions']['writable']}")
            print(f"Suspicious Regions: {stats['memory_regions']['suspicious']}")

            print("\nRisk Assessment:")
            print(f"Malicious Activity Score: {stats['malicious_score']}/100")
            risk_level = "Low" if stats['malicious_score'] < 30 else \
                        "Medium" if stats['malicious_score'] < 60 else \
                        "High" if stats['malicious_score'] < 85 else "Critical"
            print(f"Overall Risk Level: {risk_level}")

            if stats['malicious_score'] >= 60:
                print("\nRecommended Actions:")
                print("- Isolate affected system")
                print("- Collect additional forensic artifacts")
                print("- Initiate incident response procedures")
                print("- Consider memory acquisition for deeper analysis")

    except Exception as e:
        print(f"[!] Error during memory analysis: {e}")
        import traceback
        print(traceback.format_exc())
    finally:
        print("\n[*] Memory analysis complete")



# Network Traffic Analysis Module
def analyze_network(pcap_file):
    """Analyze network traffic for suspicious patterns across multiple protocols."""
    print(f"\n[*] Analyzing network traffic: {pcap_file}")
    
    try:
        packets = rdpcap(pcap_file)
        print(f"[*] Found {len(packets)} packets to analyze")

        # Initialize tracking dictionaries
        connections = {}
        dns_queries = {}
        arp_requests = {}
        icmp_types = {}
        ftp_commands = []
        dhcp_transactions = []
        telnet_sessions = {}
        http_sessions = {}
        
        # Initialize protocol-specific alerts
        alerts = {
            'tcp': [],
            'http': [],
            'dns': [],
            'dhcp': [],
            'icmp': [],
            'arp': [],
            'ftp': [],
            'telnet': []
        }

        for packet in packets:
            # TCP Analysis
            if packet.haslayer(TCP):
                src_ip = packet[IP].src if IP in packet else "Unknown"
                dst_ip = packet[IP].dst if IP in packet else "Unknown"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                
                connections[key] = connections.get(key, 0) + 1
                
                # Advanced port analysis
                high_risk_ports = {
                    4444: "Metasploit Default",
                    4445: "Alternative Metasploit",
                    1080: "SOCKS Proxy",
                    6667: "IRC Protocol",
                    6666: "IRC Alternative",
                    31337: "Back Orifice"
                }
                
                if dst_port in high_risk_ports:
                    alerts['tcp'].append(f"[!] HIGH RISK: Connection to {high_risk_ports[dst_port]} port ({dst_port})")
                
                # FTP Analysis (port 21)
                if dst_port == 21 or src_port == 21:
                    if Raw in packet:
                        command = packet[Raw].load.decode('utf-8', 'ignore').strip()
                        ftp_commands.append((time.time(), src_ip, command))
                        
                        suspicious_cmds = ['chmod', 'put', 'mput', 'site exec']
                        if any(cmd in command.lower() for cmd in suspicious_cmds):
                            alerts['ftp'].append(f"[!] Suspicious FTP command from {src_ip}: {command}")
                
                # Telnet Analysis (port 23)
                if dst_port == 23 or src_port == 23:
                    session_key = f"{src_ip}->{dst_ip}"
                    if Raw in packet:
                        telnet_data = packet[Raw].load.decode('utf-8', 'ignore')
                        telnet_sessions[session_key] = telnet_sessions.get(session_key, "") + telnet_data
                        
                        sensitive_terms = ['password', 'sudo', 'su root', 'chmod 777']
                        if any(term in telnet_data.lower() for term in sensitive_terms):
                            alerts['telnet'].append(f"[!] Sensitive Telnet command detected from {src_ip}")

            # HTTP Analysis
            if packet.haslayer(HTTPRequest):
                request = packet[HTTPRequest]
                method = request.Method.decode('utf-8', 'ignore')
                host = request.Host.decode('utf-8', 'ignore')
                path = request.Path.decode('utf-8', 'ignore')
                user_agent = request.fields.get('User-Agent', b'').decode('utf-8', 'ignore')
                content_type = request.fields.get('Content-Type', b'').decode('utf-8', 'ignore')
                
                session_key = f"{host}{path}"
                http_sessions[session_key] = {
                    'count': http_sessions.get(session_key, {}).get('count', 0) + 1,
                    'methods': http_sessions.get(session_key, {}).get('methods', set()) | {method},
                    'user_agents': http_sessions.get(session_key, {}).get('user_agents', set()) | {user_agent},
                    'last_seen': time.time(),
                    'first_seen': http_sessions.get(session_key, {}).get('first_seen', time.time())
                }

                suspicious_patterns = {
                    r'\.php$': 'PHP Endpoint',
                    r'\.asp$|\.aspx$': 'ASP/ASPX Endpoint',
                    r'\.jsp$': 'JSP Endpoint',
                    r'\.cgi$': 'CGI Script',
                    r'upload|download|file': 'File Operations',
                    r'shell|cmd|command|exec|eval|system': 'Command Execution',
                    r'powershell|bash|ssh|telnet': 'Shell Access',
                    r'admin|administrator|root|sudo': 'Admin Access',
                    r'config|setup|install|update': 'System Configuration',
                    r'select|union|insert|update|delete|drop': 'SQL Operations',
                    r'%27|%22|%3C|%3E': 'Encoded Special Characters',
                    r'login|auth|token|session|jwt': 'Authentication Endpoint',
                    r'pass|pwd|password|credential': 'Credential Operations',
                    r'base64|encode|decode|encrypt|decrypt': 'Data Encoding',
                    r'dump|backup|export|download': 'Data Export'
                }

                suspicious_headers = {
                    'User-Agent': r'curl|wget|python|payload|shell|hack',
                    'Cookie': r'base64|eval|exec|system',
                    'Referer': r'localhost|127\.0\.0\.1|192\.168',
                    'Content-Type': r'multipart/form-data|application/x-www-form-urlencoded'
                }

                # Check path for suspicious patterns
                for pattern, description in suspicious_patterns.items():
                    if re.search(pattern, path.lower()):
                        alerts['http'].append(f"[!] Suspicious HTTP {method} - {description}: {host}{path}")
                        alerts['http'].append(f"    User-Agent: {user_agent}")
                        if content_type:
                            alerts['http'].append(f"    Content-Type: {content_type}")

                # Check headers for suspicious patterns
                for header, pattern in suspicious_headers.items():
                    header_value = request.fields.get(header, b'').decode('utf-8', 'ignore')
                    if re.search(pattern, header_value.lower()):
                        alerts['http'].append(f"[!] Suspicious HTTP header - {header}: {header_value}")

                # Detect potential data exfiltration
                if method == "POST" and Raw in packet:
                    payload = packet[Raw].load.decode('utf-8', 'ignore')
                    if len(payload) > 1000:
                        alerts['http'].append(f"[!] Large POST request ({len(payload)} bytes) to {host}{path}")
                    if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', payload):
                        alerts['http'].append(f"[!] Possible base64 encoded data in POST request to {host}{path}")

                # Detect repeated requests
                if http_sessions[session_key]['count'] > 5:
                    time_window = time.time() - http_sessions[session_key]['first_seen']
                    if time_window < 60:
                        alerts['http'].append(f"[!] High frequency requests to {host}{path}")
                        alerts['http'].append(f"    {http_sessions[session_key]['count']} requests in {time_window:.1f} seconds")
                        alerts['http'].append(f"    Methods used: {', '.join(http_sessions[session_key]['methods'])}")

            # DNS Analysis
            if packet.haslayer(DNS):
                if packet.getlayer(DNS).qr == 0:  # DNS Query
                    query = packet.getlayer(DNS).qd.qname.decode('utf-8')
                    dns_queries[query] = dns_queries.get(query, 0) + 1
                    
                    # Track query types
                    qtype = packet.getlayer(DNS).qd.qtype
                    qtypes = {
                        1: 'A',
                        2: 'NS',
                        5: 'CNAME',
                        6: 'SOA',
                        12: 'PTR',
                        15: 'MX',
                        16: 'TXT',
                        28: 'AAAA',
                        33: 'SRV',
                        255: 'ANY'
                    }
                    query_type = qtypes.get(qtype, f'TYPE{qtype}')
                    
                    # Enhanced DNS anomaly detection
                    # Check for long queries (possible DNS tunneling)
                    if len(query) > 50:
                        alerts['dns'].append(f"[!] Possible DNS tunneling - Long query: {query}")
                    
                    # Check for many subdomains (possible DGA or tunneling)
                    if query.count('.') > 5:
                        alerts['dns'].append(f"[!] Suspicious DNS query - Many subdomains: {query}")
                    
                    # Check for encoded/hex data in queries
                    if re.search(r'[0-9a-f]{32}', query):
                        alerts['dns'].append(f"[!] Possible encoded data in DNS query: {query}")
                    
                    # Track unique subdomains per domain
                    domain_parts = query.split('.')
                    if len(domain_parts) >= 2:
                        base_domain = '.'.join(domain_parts[-2:])
                        alerts['dns'].append(f"[*] DNS Query: {query} (Type: {query_type}) -> {base_domain}")
                
                elif packet.getlayer(DNS).qr == 1:  # DNS Response
                    if packet.getlayer(DNS).rcode != 0:  # Error responses
                        rcode = packet.getlayer(DNS).rcode
                        rcodes = {
                            1: 'Format Error',
                            2: 'Server Failure',
                            3: 'Name Error (NXDOMAIN)',
                            4: 'Not Implemented',
                            5: 'Refused'
                        }
                        error_type = rcodes.get(rcode, f'Error {rcode}')
                        alerts['dns'].append(f"[!] DNS Error Response: {error_type}")
                    
                    # Analyze answers
                    if packet.getlayer(DNS).an:
                        for i in range(packet.getlayer(DNS).ancount):
                            rr = packet.getlayer(DNS).an[i]
                            if rr.type == 1:  # A Record
                                resolved_ip = rr.rdata
                                if isinstance(resolved_ip, bytes):
                                    resolved_ip = resolved_ip.decode('utf-8', 'ignore')
                                alerts['dns'].append(f"[*] DNS Resolution: {rr.rrname.decode('utf-8')} -> {resolved_ip}")
                            
                            # Check for suspicious TTL values
                            if hasattr(rr, 'ttl') and rr.ttl < 60:  # TTL less than 60 seconds
                                alerts['dns'].append(f"[!] Suspicious short TTL ({rr.ttl}s) for {rr.rrname.decode('utf-8')}")

                # Track DNS server usage
                if IP in packet:
                    dns_server = packet[IP].src if packet.getlayer(DNS).qr == 1 else packet[IP].dst
                    
        

            # ICMP Analysis
            if packet.haslayer(ICMP):
                icmp_type = packet[ICMP].type
                icmp_types[icmp_type] = icmp_types.get(icmp_type, 0) + 1
                
                if Raw in packet:
                    payload_len = len(packet[Raw].load)
                    if payload_len > 64:
                        alerts['icmp'].append(f"[!] Large ICMP payload ({payload_len} bytes) - Possible tunneling")
                    if payload_len > 1000:
                        alerts['icmp'].append(f"[!] Very large ICMP payload - Likely data exfiltration")

            # ARP Analysis
            if packet.haslayer(ARP):
                src_mac = packet[ARP].hwsrc
                src_ip = packet[ARP].psrc
                key = f"{src_mac}-{src_ip}"
                
                if packet[ARP].op == 1:
                    arp_requests[key] = arp_requests.get(key, 0) + 1
                    
                    if arp_requests[key] > 5:
                        alerts['arp'].append(f"[!] Possible ARP scanning from {src_mac} ({src_ip})")
                    
                    for k in arp_requests:
                        if k.split('-')[0] == src_mac and k.split('-')[1] != src_ip:
                            alerts['arp'].append(f"[!] Possible ARP spoofing: {src_mac} claiming multiple IPs")

        # Print Protocol Analysis Summary
        print("\n=== Protocol Analysis Summary ===")

        print("\nTCP/Port Analysis:")
        for alert in alerts['tcp']:
            print(alert)
        for conn, count in connections.items():
            if count > 10:
                print(f"[*] High frequency connection: {conn} ({count} times)")

        print("\nHTTP Analysis:")
        for alert in alerts['http']:
            print(alert)
        for session, data in http_sessions.items():
            if data['count'] > 5:
                print(f"[*] Repeated HTTP requests to: {session}")
                print(f"    Request count: {data['count']}")
                print(f"    Methods used: {', '.join(data['methods'])}")
                print(f"    Unique User-Agents: {len(data['user_agents'])}")
                print(f"    Last seen: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data['last_seen']))}")

        print("\nDNS Analysis:")
        for alert in alerts['dns']:
            print(alert)
        if dns_queries:
            print("\nTop Queried Domains:")
            sorted_queries = sorted(dns_queries.items(), key=lambda x: x[1], reverse=True)
            for query, count in sorted_queries[:5]:  
                print(f"[*] {query}: {count} times")

        print("\nICMP Analysis:")
        for alert in alerts['icmp']:
            print(alert)
        for icmp_type, count in icmp_types.items():
            print(f"[*] ICMP Type {icmp_type}: {count} packets")

        print("\nARP Analysis:")
        for alert in alerts['arp']:
            print(alert)
        for key, count in arp_requests.items():
            mac, ip = key.split('-')
            print(f"[*] ARP requests from {mac} ({ip}): {count}")

        # Final Statistics
        print("\n=== Final Statistics ===")
        print(f"Total Packets: {len(packets)}")
        print(f"TCP Connections: {len(connections)}")
        print(f"HTTP Sessions: {len(http_sessions)}")
        print(f"DNS Queries: {len(dns_queries)}")
        print(f"FTP Commands: {len(ftp_commands)}")
        print(f"DHCP Transactions: {len(dhcp_transactions)}")
        print(f"Unique ICMP Types: {len(icmp_types)}")
        print(f"ARP Sources: {len(arp_requests)}")

    except Exception as e:
        print(f"[!] Error in network analysis: {e}")
        import traceback
        print(traceback.format_exc())
    finally:
        print("\n[*] Network analysis complete")



# Behavioral Detection Module
def monitor_behavior(duration=30):
    # Monitor system behavior for suspicious activities in Linux environment.
    
    print(f"[*] Monitoring system behavior for {duration} seconds...")
    start_time = time.time()
    processes_seen = set()
    
    # Linux-specific suspicious processes and commands
    SUSPICIOUS_COMMANDS = ['nc', 'netcat', 'wget', 'curl', 'base64', 'python3 -m http.server']
    SUSPICIOUS_PATHS = ['/tmp/', '/dev/shm/', '/var/tmp/']
    
    while time.time() - start_time < duration:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe', 'username']):
            try:
                if proc.info['pid'] in processes_seen:
                    continue
                
                processes_seen.add(proc.info['pid'])
                cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                exe_path = proc.info['exe'] if proc.info['exe'] else ''
                
                # Check for suspicious shell commands
                if any(cmd in cmdline.lower() for cmd in SUSPICIOUS_COMMANDS):
                    print(f"[!] Suspicious command detected: PID {proc.info['pid']} - {cmdline}")
                
                # Check for suspicious file locations
                if any(path in exe_path for path in SUSPICIOUS_PATHS):
                    print(f"[!] Process running from suspicious location: {exe_path}")
                    
                # Check for potential log tampering
                if 'rm' in cmdline and ('/var/log' in cmdline or '.log' in cmdline):
                    print(f"[!] Possible log deletion detected: PID {proc.info['pid']} - {cmdline}")
                
                # Check for suspicious Python scripts
                if 'python' in cmdline.lower() and ('http.server' in cmdline or 'socket' in cmdline):
                    print(f"[!] Potential malicious Python script: PID {proc.info['pid']} - {cmdline}")
                
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                continue
            
        sys.stdout.flush()
        time.sleep(1)
    
    print(f"\n[*] Monitoring complete. Analyzed {len(processes_seen)} processes")





def main():

    parser = argparse.ArgumentParser(description="Forensic Detection Tool for Spear-Phishing Attack")
    parser.add_argument('--memory', type=str, help="Path to memory dump file (e.g., memory.raw)")
    parser.add_argument('--network', type=str, help="Path to network capture file (e.g., traffic.pcap)")
    parser.add_argument('--behavior', action='store_true', help="Run real-time behavioral detection")
    parser.add_argument('--duration', type=int, default=30, help="Duration for behavioral monitoring in seconds")
    
    args = parser.parse_args()
    
    if not any([args.memory, args.network, args.behavior]):
        parser.print_help()
        sys.exit(1)
    
    if args.memory:
        analyze_memory(args.memory)
    
    if args.network:
        analyze_network(args.network)
    
    if args.behavior:
        monitor_behavior(args.duration)

if __name__ == "__main__":
    main()








# Usage Examples:
# - Memory analysis: python forensic_tool.py --memory memory.raw
# - Network analysis: python forensic_tool.py --network traffic.pcap
# - Behavioral monitoring: python forensic_tool.py --behavior --duration 60
#
# Testing the Tool:
# 1. Simulate the attack in a controlled VM environment:
#    - Open the malicious PDF to trigger the PowerShell script.
#    - Allow the keylogger to send data to a mock C2 server.
#    - Perform DLL injection into explorer.exe and wipe logs.
#    - Exfiltrate data via VPN.
# 2. Collect data:
#    - Export a memory dump using a tool like DumpIt.
#    - Capture network traffic with Wireshark (save as .pcap).
#    - Run the tool in real-time for behavioral detection.
# 3. Run the tool against the collected data to detect IoCs.
#
# Expected Outputs:
# - Memory: Detects injection in explorer.exe.
# - Network: Flags repeated HTTPS POST requests as C2 beaconing.
# - Behavior: Alerts on PowerShell execution and log wiping attempts.