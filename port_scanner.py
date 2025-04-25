import socket
from datetime import datetime

# Known vulnerabilities (basic hints by port)
vulnerabilities = {
    21: "FTP - Check for anonymous login",
    22: "SSH - Weak ciphers possible",
    23: "Telnet - Insecure protocol",
    25: "SMTP - Open relay risk",
    53: "DNS - May allow zone transfer",
    80: "HTTP - Unencrypted traffic",
    110: "POP3 - Weak password security",
    139: "NetBIOS - Vulnerable to SMB exploits",
    143: "IMAP - Plaintext credentials possible",
    443: "HTTPS - Check SSL/TLS version",
    445: "SMB - Target of many exploits (e.g. EternalBlue)",
    3306: "MySQL - Default config may expose data",
    3389: "RDP - Remote desktop exposed",
}

# Ask the user for target IP
target = input("Enter target IP address: ")

# Ask the user for port range
start_port = int(input("Enter start port: "))
end_port = int(input("Enter end port: "))

print(f"\nScanning target {target} from port {start_port} to {end_port}...")
start_time = datetime.now()

# List to hold open ports
open_ports = []

# Scan the ports
for port in range(start_port, end_port + 1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(0.5)  # Timeout for connection attempt

    result = sock.connect_ex((target, port))
    if result == 0:
        message = f"Port {port}: OPEN"
        if port in vulnerabilities:
            message += f" → ⚠️ {vulnerabilities[port]}"
        print(message)
        open_ports.append(port)
    sock.close()

# Scan completed
end_time = datetime.now()
total_time = end_time - start_time

print(f"\nScanning completed in: {total_time}")
print(f"Total open ports found: {len(open_ports)}")

# Save open ports to a text file
with open("open_ports.txt", "w") as f:
    if open_ports:
        f.write(f"Open ports for {target}:\n")
        for port in open_ports:
            vuln = vulnerabilities.get(port, "")
            line = f"Port {port}: OPEN"
            if vuln:
                line += f" → {vuln}"
            f.write(line + "\n")
    else:
        f.write(f"No open ports found on {target} in range {start_port}-{end_port}.\n")

print("\nResults saved to open_ports.txt")
