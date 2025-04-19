import socket
import threading
import time
import csv
import os
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    print("Colorama not installed. Output will not be colored.")
    print("Install with: pip install colorama")
    
try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False
    print("Tabulate not installed. Output will not be formatted in tables.")
    print("Install with: pip install tabulate")

COMMON_SERVICES = {
    "20": {"name": "FTP-DATA", "protocol": "TCP", "description": "File Transfer Protocol (Data Channel)"},
    "21": {"name": "FTP", "protocol": "TCP", "description": "File Transfer Protocol"},
    "22": {"name": "SSH", "protocol": "TCP", "description": "Secure Shell"},
    "23": {"name": "Telnet", "protocol": "TCP", "description": "Telnet protocol"},
    "25": {"name": "SMTP", "protocol": "TCP", "description": "Simple Mail Transfer Protocol"},
    "37": {"name": "TIME", "protocol": "TCP/UDP", "description": "Time Protocol"},
    "43": {"name": "WHOIS", "protocol": "TCP", "description": "WHOIS Protocol"},
    "49": {"name": "TACACS", "protocol": "TCP/UDP", "description": "Terminal Access Controller Access-Control System"},
    "53": {"name": "DNS", "protocol": "TCP/UDP", "description": "Domain Name System"},
    "67": {"name": "DHCP", "protocol": "UDP", "description": "Dynamic Host Configuration Protocol (Server)"},
    "68": {"name": "DHCP", "protocol": "UDP", "description": "Dynamic Host Configuration Protocol (Client)"},
    "69": {"name": "TFTP", "protocol": "UDP", "description": "Trivial File Transfer Protocol"},
    "79": {"name": "Finger", "protocol": "TCP", "description": "Finger Protocol"},
    "80": {"name": "HTTP", "protocol": "TCP", "description": "Hypertext Transfer Protocol"},
    "88": {"name": "Kerberos", "protocol": "TCP/UDP", "description": "Kerberos Authentication System"},
    "102": {"name": "ISO-TSAP", "protocol": "TCP", "description": "ISO Transport Service Access Point"},
    "110": {"name": "POP3", "protocol": "TCP", "description": "Post Office Protocol v3"},
    "111": {"name": "RPC", "protocol": "TCP/UDP", "description": "Remote Procedure Call"},
    "113": {"name": "Ident", "protocol": "TCP", "description": "Authentication Service/Identification Protocol"},
    "115": {"name": "SFTP", "protocol": "TCP", "description": "Secure File Transfer Protocol"},
    "119": {"name": "NNTP", "protocol": "TCP", "description": "Network News Transfer Protocol"},
    "123": {"name": "NTP", "protocol": "UDP", "description": "Network Time Protocol"},
    "135": {"name": "EPMAP", "protocol": "TCP/UDP", "description": "DCE endpoint resolution/Microsoft EPMAP"},
    "137": {"name": "NetBIOS-NS", "protocol": "TCP/UDP", "description": "NetBIOS Name Service"},
    "138": {"name": "NetBIOS-DGM", "protocol": "UDP", "description": "NetBIOS Datagram Service"},
    "139": {"name": "NetBIOS-SSN", "protocol": "TCP", "description": "NetBIOS Session Service"},
    "143": {"name": "IMAP", "protocol": "TCP", "description": "Internet Message Access Protocol"},
    "161": {"name": "SNMP", "protocol": "UDP", "description": "Simple Network Management Protocol"},
    "162": {"name": "SNMPTRAP", "protocol": "TCP/UDP", "description": "SNMP Trap"},
    "179": {"name": "BGP", "protocol": "TCP", "description": "Border Gateway Protocol"},
    "194": {"name": "IRC", "protocol": "TCP", "description": "Internet Relay Chat"},
    "201": {"name": "AppleTalk", "protocol": "TCP/UDP", "description": "AppleTalk Routing Maintenance"},
    "220": {"name": "IMAP3", "protocol": "TCP", "description": "Interactive Mail Access Protocol v3"},
    "389": {"name": "LDAP", "protocol": "TCP/UDP", "description": "Lightweight Directory Access Protocol"},
    "427": {"name": "SLP", "protocol": "TCP/UDP", "description": "Service Location Protocol"},
    "443": {"name": "HTTPS", "protocol": "TCP", "description": "HTTP Secure"},
    "444": {"name": "SNPP", "protocol": "TCP", "description": "Simple Network Paging Protocol"},
    "445": {"name": "SMB", "protocol": "TCP", "description": "Server Message Block"},
    "464": {"name": "Kerberos", "protocol": "TCP/UDP", "description": "Kerberos Change/Set password"},
    "465": {"name": "SMTPS", "protocol": "TCP", "description": "SMTP over SSL"},
    "500": {"name": "IKE", "protocol": "UDP", "description": "Internet Key Exchange"},
    "513": {"name": "rlogin", "protocol": "TCP", "description": "Remote Login"},
    "514": {"name": "Syslog", "protocol": "UDP", "description": "Syslog"},
    "515": {"name": "LPD", "protocol": "TCP", "description": "Line Printer Daemon"},
    "520": {"name": "RIP", "protocol": "UDP", "description": "Routing Information Protocol"},
    "530": {"name": "RPC", "protocol": "TCP/UDP", "description": "Remote Procedure Call"},
    "543": {"name": "Klogin", "protocol": "TCP", "description": "Kerberos Login"},
    "544": {"name": "Kshell", "protocol": "TCP", "description": "Kerberos Remote Shell"},
    "546": {"name": "DHCPv6", "protocol": "TCP/UDP", "description": "DHCPv6 Client"},
    "547": {"name": "DHCPv6", "protocol": "TCP/UDP", "description": "DHCPv6 Server"},
    "554": {"name": "RTSP", "protocol": "TCP", "description": "Real Time Streaming Protocol"},
    "563": {"name": "NNTPS", "protocol": "TCP", "description": "NNTP over SSL"},
    "587": {"name": "SMTP", "protocol": "TCP", "description": "SMTP (submission)"},
    "593": {"name": "RPC-HTTP", "protocol": "TCP", "description": "HTTP RPC Endpoint Mapper"},
    "631": {"name": "IPP", "protocol": "TCP/UDP", "description": "Internet Printing Protocol"},
    "636": {"name": "LDAPS", "protocol": "TCP", "description": "LDAP over SSL"},
    "646": {"name": "LDP", "protocol": "TCP/UDP", "description": "Label Distribution Protocol"},
    "691": {"name": "MS-Exchange", "protocol": "TCP", "description": "MS Exchange Routing"},
    "860": {"name": "iSCSI", "protocol": "TCP", "description": "iSCSI"},
    "873": {"name": "rsync", "protocol": "TCP", "description": "rsync File Synchronization Protocol"},
    "902": {"name": "VMware", "protocol": "TCP", "description": "VMware Server Console"},
    "989": {"name": "FTPS", "protocol": "TCP", "description": "FTP over SSL (data)"},
    "990": {"name": "FTPS", "protocol": "TCP", "description": "FTP over SSL (control)"},
    "993": {"name": "IMAPS", "protocol": "TCP", "description": "IMAP over SSL"},
    "995": {"name": "POP3S", "protocol": "TCP", "description": "POP3 over SSL"},
    "1025": {"name": "NFS", "protocol": "TCP", "description": "Microsoft RPC/NFS"},
    "1080": {"name": "SOCKS", "protocol": "TCP", "description": "SOCKS Proxy"},
    "1194": {"name": "OpenVPN", "protocol": "TCP/UDP", "description": "OpenVPN"},
    "1293": {"name": "IPSec", "protocol": "TCP/UDP", "description": "IPSec"},
    "1337": {"name": "WASTE", "protocol": "TCP", "description": "WASTE Encrypted File Sharing"},
    "1433": {"name": "MSSQL", "protocol": "TCP", "description": "Microsoft SQL Server"},
    "1434": {"name": "MSSQL", "protocol": "UDP", "description": "Microsoft SQL Monitor"},
    "1521": {"name": "Oracle", "protocol": "TCP", "description": "Oracle Database"},
    "1527": {"name": "Derby", "protocol": "TCP", "description": "Apache Derby Database"},
    "1701": {"name": "L2TP", "protocol": "UDP", "description": "Layer 2 Tunneling Protocol"},
    "1720": {"name": "H.323", "protocol": "TCP", "description": "H.323 Call Signaling"},
    "1723": {"name": "PPTP", "protocol": "TCP", "description": "Point-to-Point Tunneling Protocol"},
    "1812": {"name": "RADIUS", "protocol": "UDP", "description": "RADIUS Authentication Protocol"},
    "1813": {"name": "RADIUS", "protocol": "UDP", "description": "RADIUS Accounting Protocol"},
    "1863": {"name": "MSN", "protocol": "TCP", "description": "Microsoft Notification Protocol"},
    "1900": {"name": "SSDP", "protocol": "UDP", "description": "Simple Service Discovery Protocol"},
    "1935": {"name": "RTMP", "protocol": "TCP", "description": "Real-Time Messaging Protocol"},
    "2000": {"name": "Cisco SCCP", "protocol": "TCP", "description": "Cisco Skinny Client Control Protocol"},
    "2049": {"name": "NFS", "protocol": "TCP/UDP", "description": "Network File System"},
    "2082": {"name": "cPanel", "protocol": "TCP", "description": "cPanel Default"},
    "2083": {"name": "cPanel", "protocol": "TCP", "description": "cPanel Default SSL"},
    "2086": {"name": "WHM", "protocol": "TCP", "description": "WebHost Manager"},
    "2087": {"name": "WHM", "protocol": "TCP", "description": "WebHost Manager SSL"},
    "2095": {"name": "Webmail", "protocol": "TCP", "description": "cPanel Webmail"},
    "2096": {"name": "Webmail", "protocol": "TCP", "description": "cPanel Webmail SSL"},
    "2181": {"name": "ZooKeeper", "protocol": "TCP", "description": "Apache ZooKeeper"},
    "2222": {"name": "DirectAdmin", "protocol": "TCP", "description": "DirectAdmin Control Panel"},
    "2375": {"name": "Docker", "protocol": "TCP", "description": "Docker REST API (unencrypted)"},
    "2376": {"name": "Docker", "protocol": "TCP", "description": "Docker REST API (SSL)"},
    "2483": {"name": "Oracle", "protocol": "TCP", "description": "Oracle DB Listener"},
    "2484": {"name": "Oracle", "protocol": "TCP", "description": "Oracle DB Listener (SSL)"},
    "2638": {"name": "Sybase", "protocol": "TCP", "description": "Sybase Database"},
    "3260": {"name": "iSCSI", "protocol": "TCP", "description": "iSCSI Target"},
    "3269": {"name": "LDAP", "protocol": "TCP", "description": "Global Catalog LDAP SSL"},
    "3306": {"name": "MySQL", "protocol": "TCP", "description": "MySQL Database"},
    "3389": {"name": "RDP", "protocol": "TCP", "description": "Remote Desktop Protocol"},
    "3478": {"name": "STUN", "protocol": "TCP/UDP", "description": "STUN/TURN Server"},
    "3690": {"name": "SVN", "protocol": "TCP", "description": "Subversion"},
    "4125": {"name": "IGP", "protocol": "UDP", "description": "Cisco Interior Gateway Protocol"},
    "4369": {"name": "EPMD", "protocol": "TCP", "description": "Erlang Port Mapper Daemon"},
    "4443": {"name": "Pharos", "protocol": "TCP", "description": "Pharos Communications"},
    "4505": {"name": "SaltStack", "protocol": "TCP", "description": "SaltStack Master Publisher"},
    "4506": {"name": "SaltStack", "protocol": "TCP", "description": "SaltStack Master Command"},
    "4569": {"name": "IAX", "protocol": "UDP", "description": "Inter-Asterisk eXchange"},
    "5060": {"name": "SIP", "protocol": "TCP/UDP", "description": "Session Initiation Protocol"},
    "5061": {"name": "SIP", "protocol": "TCP", "description": "SIP over TLS"},
    "5222": {"name": "XMPP", "protocol": "TCP", "description": "XMPP Client Connection"},
    "5269": {"name": "XMPP", "protocol": "TCP", "description": "XMPP Server Connection"},
    "5353": {"name": "mDNS", "protocol": "UDP", "description": "Multicast DNS"},
    "5432": {"name": "PostgreSQL", "protocol": "TCP", "description": "PostgreSQL Database"},
    "5631": {"name": "pcANYWHERE", "protocol": "TCP", "description": "pcANYWHERE Data"},
    "5666": {"name": "NRPE", "protocol": "TCP", "description": "Nagios Remote Plugin Executor"},
    "5672": {"name": "AMQP", "protocol": "TCP", "description": "Advanced Message Queuing Protocol"},
    "5683": {"name": "CoAP", "protocol": "UDP", "description": "Constrained Application Protocol"},
    "5800": {"name": "VNC", "protocol": "TCP", "description": "VNC over HTTP"},
    "5900": {"name": "VNC", "protocol": "TCP", "description": "Virtual Network Computing"},
    "5901": {"name": "VNC-1", "protocol": "TCP", "description": "VNC Display 1"},
    "5985": {"name": "WinRM", "protocol": "TCP", "description": "Windows Remote Management HTTP"},
    "5986": {"name": "WinRM", "protocol": "TCP", "description": "Windows Remote Management HTTPS"},
    "6379": {"name": "Redis", "protocol": "TCP", "description": "Redis Database"},
    "6514": {"name": "Syslog", "protocol": "TCP", "description": "Syslog over TLS"},
    "6566": {"name": "SANE", "protocol": "TCP", "description": "SANE Scanner Control"},
    "6667": {"name": "IRC", "protocol": "TCP", "description": "Internet Relay Chat"},
    "6881": {"name": "BitTorrent", "protocol": "TCP", "description": "BitTorrent"},
    "7001": {"name": "WebLogic", "protocol": "TCP", "description": "Oracle WebLogic Server"},
    "7396": {"name": "Alternate", "protocol": "TCP", "description": "Web Management Console"},
    "7474": {"name": "Neo4j", "protocol": "TCP", "description": "Neo4j Database"},
    "8000": {"name": "HTTP Alt", "protocol": "TCP", "description": "Alternative HTTP Port"},
    "8008": {"name": "HTTP", "protocol": "TCP", "description": "Alternative HTTP Port"},
    "8009": {"name": "AJP", "protocol": "TCP", "description": "Apache JServ Protocol"},
    "8080": {"name": "HTTP-ALT", "protocol": "TCP", "description": "Alternative HTTP Port"},
    "8081": {"name": "HTTP-ALT", "protocol": "TCP", "description": "Alternative HTTP Port"},
    "8086": {"name": "InfluxDB", "protocol": "TCP", "description": "InfluxDB Database"},
    "8088": {"name": "Hadoop", "protocol": "TCP", "description": "Hadoop Resource Manager"},
    "8333": {"name": "Bitcoin", "protocol": "TCP", "description": "Bitcoin"},
    "8443": {"name": "HTTPS-ALT", "protocol": "TCP", "description": "Alternative HTTPS Port"},
    "8883": {"name": "MQTT", "protocol": "TCP", "description": "Secure MQTT"},
    "8888": {"name": "HTTP-ALT", "protocol": "TCP", "description": "Alternative HTTP Port"},
    "9000": {"name": "SonarQube", "protocol": "TCP", "description": "SonarQube Web Server"},
    "9042": {"name": "Cassandra", "protocol": "TCP", "description": "Apache Cassandra"},
    "9090": {"name": "Prometheus", "protocol": "TCP", "description": "Prometheus Metrics"},
    "9091": {"name": "Transmission", "protocol": "TCP", "description": "Transmission Web Interface"},
    "9092": {"name": "Kafka", "protocol": "TCP", "description": "Apache Kafka"},
    "9200": {"name": "Elasticsearch", "protocol": "TCP", "description": "Elasticsearch HTTP"},
    "9300": {"name": "Elasticsearch", "protocol": "TCP", "description": "Elasticsearch Transport"},
    "9418": {"name": "Git", "protocol": "TCP", "description": "Git Protocol"},
    "9999": {"name": "Urchin", "protocol": "TCP", "description": "Urchin Web Analytics"},
    "10000": {"name": "Webmin", "protocol": "TCP", "description": "Webmin Administration"},
    "11211": {"name": "Memcached", "protocol": "TCP/UDP", "description": "Memcached"},
    "15672": {"name": "RabbitMQ", "protocol": "TCP", "description": "RabbitMQ Management Console"},
    "16992": {"name": "Intel AMT", "protocol": "TCP", "description": "Intel AMT Remote Management"},
    "19132": {"name": "Minecraft", "protocol": "UDP", "description": "Minecraft Bedrock Edition"},
    "25565": {"name": "Minecraft", "protocol": "TCP", "description": "Minecraft Java Edition"},
    "27017": {"name": "MongoDB", "protocol": "TCP", "description": "MongoDB Database"},
    "27018": {"name": "MongoDB", "protocol": "TCP", "description": "MongoDB Shard Server"},
    "27019": {"name": "MongoDB", "protocol": "TCP", "description": "MongoDB Config Server"},
    "28017": {"name": "MongoDB", "protocol": "TCP", "description": "MongoDB Web Status Page"},
    "32400": {"name": "Plex", "protocol": "TCP", "description": "Plex Media Server"},
    "49152": {"name": "Dynamic", "protocol": "TCP/UDP", "description": "First Dynamic/Private Port"},
    "65535": {"name": "Dynamic", "protocol": "TCP/UDP", "description": "Last Dynamic/Private Port"}
}

def colored_text(text, color=None):
    """Apply color to text if colorama is available"""
    if COLORS_AVAILABLE and color:
        colors = {
            "red": Fore.RED,
            "green": Fore.GREEN,
            "yellow": Fore.YELLOW,
            "blue": Fore.BLUE,
            "magenta": Fore.MAGENTA,
            "cyan": Fore.CYAN,
            "white": Fore.WHITE,
        }
        return f"{colors.get(color, '')}{text}{Style.RESET_ALL}"
    return text

def get_service_info(port):
    """Get service information for a given port"""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    
    try:
        service_name = socket.getservbyport(port)
        return {
            "name": service_name,
            "protocol": "TCP", 
            "description": f"Service on port {port}"
        }
    except (socket.error, OSError):
        return {
            "name": "Unknown",
            "protocol": "TCP",
            "description": "Unknown service"
        }

def scan_port(target, port, timeout):
    """Scan a single port and return the result"""
    start_time = time.time()
    result = {
        "port": port,
        "status": "Closed",
        "response_time": 0,
        "service_name": "N/A",
        "protocol": "TCP",
        "description": "N/A"
    }
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        connection = s.connect_ex((target, port))
        end_time = time.time()
        response_time = round((end_time - start_time) * 1000, 2)  # in ms
        
        if connection == 0:
            service_info = get_service_info(port)
            result.update({
                "status": "Open",
                "response_time": response_time,
                "service_name": service_info["name"],
                "protocol": service_info["protocol"],
                "description": service_info["description"]
            })
        s.close()
    except socket.error:
        pass
    
    return result

def validate_ip(ip):
    """Validate if the provided string is a valid IP address"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_port_range(port_range):
    """Validate and parse the port range string"""
    try:
        if "-" in port_range:
            start, end = map(int, port_range.split("-"))
            if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                return start, end
        else:
            port = int(port_range)
            if 1 <= port <= 65535:
                return port, port
    except ValueError:
        pass
    
    return None, None

def save_results_to_file(results, filename):
    """Save scan results to a CSV file"""
    try:
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['Port', 'Status', 'Protocol', 'Service', 'Response Time (ms)', 'Description']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                writer.writerow({
                    'Port': result['port'],
                    'Status': result['status'],
                    'Protocol': result['protocol'],
                    'Service': result['service_name'],
                    'Response Time (ms)': result['response_time'],
                    'Description': result['description']
                })
        return True
    except Exception as e:
        print(f"Error saving results: {e}")
        return False

def display_results(results):
    """Display scan results in a formatted table"""
    open_ports = [r for r in results if r['status'] == 'Open']
    
    if not open_ports:
        print(colored_text("\nNo open ports found.", "yellow"))
        return
    
    print(colored_text(f"\nFound {len(open_ports)} open ports:", "green"))
    
    if TABULATE_AVAILABLE:
        table_data = []
        for result in open_ports:
            table_data.append([
                colored_text(str(result['port']), "cyan"),
                colored_text(result['status'], "green"),
                result['protocol'],
                result['service_name'],
                f"{result['response_time']} ms",
                result['description']
            ])
        
        headers = ["Port", "Status", "Protocol", "Service", "Response Time", "Description"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
    else:
        for result in open_ports:
            status_color = "green" if result['status'] == "Open" else "red"
            print(f"Port: {colored_text(str(result['port']), 'cyan')}")
            print(f"Status: {colored_text(result['status'], status_color)}")
            print(f"Protocol: {result['protocol']}")
            print(f"Service: {result['service_name']}")
            print(f"Response Time: {result['response_time']} ms")
            print(f"Description: {result['description']}")
            print("-" * 50)

def main():
    """Main function to run the port scanner"""
    print(colored_text("=" * 60, "blue"))
    print(colored_text("           PYTHON PORT SCANNER", "cyan"))
    print(colored_text("=" * 60, "blue"))
    
    while True:
        target = input(colored_text("Enter target IP address: ", "cyan"))
        if validate_ip(target):
            break
        print(colored_text("Invalid IP address. Please try again.", "red"))
    
    while True:
        port_range = input(colored_text("Enter port range (e.g., 1-100) or single port: ", "cyan"))
        start_port, end_port = validate_port_range(port_range)
        if start_port is not None:
            break
        print(colored_text("Invalid port range. Please enter a valid range (1-65535).", "red"))
    
    while True:
        try:
            timeout = float(input(colored_text("Enter timeout in seconds (Best - 0.1): ", "cyan")) or 1.0)
            if timeout > 0:
                break
            print(colored_text("Timeout must be greater than 0.", "red"))
        except ValueError:
            print(colored_text("Invalid timeout. Please enter a valid number.", "red"))
    
    while True:
        try:
            max_threads = int(input(colored_text("Enter number of threads (Best - 50): ", "cyan")) or 100)
            if max_threads > 0:
                break
            print(colored_text("Thread count must be greater than 0.", "red"))
        except ValueError:
            print(colored_text("Invalid thread count. Please enter a valid number.", "red"))
    
    print(colored_text("\nStarting scan...", "yellow"))
    print(f"Target: {colored_text(target, 'green')}")
    print(f"Port range: {colored_text(f'{start_port}-{end_port}', 'green')}")
    print(f"Timeout: {colored_text(f'{timeout} seconds', 'green')}")
    print(f"Threads: {colored_text(str(max_threads), 'green')}")
    
    start_time = time.time()
    
    ports = list(range(start_port, end_port + 1))
    total_ports = len(ports)
    
    results = []
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_port, target, port, timeout) for port in ports]
        
        for future in tqdm(futures, total=total_ports, desc="Scanning", unit="port"):
            result = future.result()
            results.append(result)
    
    end_time = time.time()
    scan_duration = round(end_time - start_time, 2)
    
    display_results(results)
    
    print(colored_text(f"\nScan completed in {scan_duration} seconds.", "yellow"))
    
    save_option = input(colored_text("\nDo you want to save the results to a file? (y/n): ", "cyan")).lower()
    if save_option == 'y':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"port_scan_{target}_{timestamp}.csv"
        filename = input(colored_text(f"Enter filename (default: {default_filename}): ", "cyan")) or default_filename
        
        if save_results_to_file(results, filename):
            print(colored_text(f"Results saved to {filename}", "green"))
        else:
            print(colored_text("Failed to save results.", "red"))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored_text("\nScan aborted by user.", "red"))
    except Exception as e:
        print(colored_text(f"\nAn error occurred: {e}", "red"))
    finally:
        print(colored_text("\nExiting port scanner.", "yellow"))
