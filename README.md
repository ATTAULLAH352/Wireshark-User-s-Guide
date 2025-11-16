# Wireshark Comprehensive Guide

<div align="center">

![Wireshark Logo](https://upload.wikimedia.org/wikipedia/commons/c/c6/Wireshark_icon_new.png)

**The Ultimate Guide to Network Protocol Analysis with Wireshark**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Wireshark](https://img.shields.io/badge/Wireshark-3.x+-blue.svg)](https://www.wireshark.org/)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

---

## 📑 Table of Contents

- [Introduction](#introduction)
- [Part 1: Wireshark Basics](#part-1-wireshark-basics)
  - [Getting Started](#getting-started)
  - [Tool Overview](#tool-overview)
  - [Packet Dissection](#packet-dissection)
  - [Packet Navigation](#packet-navigation)
  - [Packet Filtering](#packet-filtering)
- [Part 2: Packet Operations](#part-2-packet-operations)
  - [Statistics Overview](#statistics-overview)
  - [Protocol Details](#protocol-details)
  - [Filtering Principles](#filtering-principles)
  - [Advanced Filtering](#advanced-filtering)
- [Part 3: Traffic Analysis](#part-3-traffic-analysis)
  - [Nmap Scan Detection](#nmap-scan-detection)
  - [ARP Poisoning/MITM](#arp-poisoning-mitm)
  - [Host Identification](#host-identification)
  - [Tunneling Traffic](#tunneling-traffic)
  - [Protocol Analysis](#protocol-analysis)
  - [Credential Hunting](#credential-hunting)
- [Best Practices](#best-practices)
- [Resources](#resources)

---

## 🎯 Introduction

**Wireshark** is the world's most widely-used network protocol analyzer. It lets you capture and interactively browse the traffic running on a computer network in real-time. This guide provides a comprehensive walkthrough from basics to advanced traffic analysis.

### Why Wireshark?

- 🔍 **Deep Inspection**: Examine hundreds of protocols at microscopic detail
- 🎨 **Rich VoIP Analysis**: Decode voice and video calls
- 🔓 **Decryption Support**: Decrypt SSL/TLS, WPA/WPA2, and more
- 📊 **Powerful Statistics**: Generate comprehensive network statistics
- 🖥️ **Cross-Platform**: Available on Windows, Linux, macOS, and more

---

## 🚀 Part 1: Wireshark Basics

### Getting Started

#### Installation

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install wireshark

# macOS (using Homebrew)
brew install --cask wireshark

# Windows
# Download from https://www.wireshark.org/download.html
```

#### First Launch

```bash
# Linux - run with proper permissions
sudo wireshark

# Or add your user to wireshark group
sudo usermod -aG wireshark $USER
# Log out and back in for changes to take effect
```

---

### Tool Overview

#### User Interface Components

The Wireshark UI consists of several key areas:

```
┌─────────────────────────────────────────────────────┐
│  Menu Bar & Toolbar                                 │
├─────────────────────────────────────────────────────┤
│  Display Filter Bar                                 │
├─────────────────────────────────────────────────────┤
│  Packet List Pane (Summary of all packets)         │
├─────────────────────────────────────────────────────┤
│  Packet Details Pane (Protocol tree)               │
├─────────────────────────────────────────────────────┤
│  Packet Bytes Pane (Hexadecimal + ASCII)           │
├─────────────────────────────────────────────────────┤
│  Status Bar                                         │
└─────────────────────────────────────────────────────┘
```

#### Loading PCAP Files

**Method 1: File Menu**
```
File → Open → Select your .pcap or .pcapng file
```

**Method 2: Command Line**
```bash
wireshark capture.pcap
```

**Method 3: Drag and Drop**
- Simply drag a .pcap file into the Wireshark window

#### Example: Opening a Sample Capture

```bash
# Download a sample capture
wget https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=http.cap

# Open it
wireshark http.cap
```

#### Capture File Properties

View important metadata about your capture file:

```
Statistics → Capture File Properties
```

**Key Information Displayed:**
- File name and path
- File size and format
- Capture duration
- Number of packets
- Average packet rate
- Data rate
- Interface information

**Example Output:**
```
File:               http.cap
Length:             43 kB
Format:             Wireshark/tcpdump/... - pcap
Encapsulation:      Ethernet
Time:               First packet: 2004-05-13 10:17:07
                    Last packet:  2004-05-13 10:17:08
Packets:            43
Average pps:        40.5
```

---

### Packet Dissection

Understanding how Wireshark breaks down packets into layers.

#### Protocol Layers (OSI Model Mapping)

```
Application Layer    ┐
Presentation Layer   ├─→ Layer 7: HTTP, DNS, FTP, etc.
Session Layer        ┘

Transport Layer      ───→ Layer 4: TCP, UDP

Network Layer        ───→ Layer 3: IP, ICMP

Data Link Layer      ───→ Layer 2: Ethernet, ARP

Physical Layer       ───→ Layer 1: Raw bits
```

#### Reading Packet Layers

When you select a packet, the **Packet Details Pane** shows:

**Example: HTTP GET Request**

```
▼ Frame 1: 74 bytes on wire (592 bits), 74 bytes captured
  ├─ Interface: eth0
  ├─ Arrival Time: May 13, 2004 10:17:07.311224000 PDT
  └─ Frame Length: 74 bytes

▼ Ethernet II, Src: 00:11:22:33:44:55, Dst: aa:bb:cc:dd:ee:ff
  ├─ Destination: aa:bb:cc:dd:ee:ff
  ├─ Source: 00:11:22:33:44:55
  └─ Type: IPv4 (0x0800)

▼ Internet Protocol Version 4, Src: 192.168.1.100, Dst: 93.184.216.34
  ├─ Version: 4
  ├─ Header Length: 20 bytes
  ├─ Total Length: 60
  ├─ Identification: 0x1234
  ├─ Flags: 0x4000, Don't fragment
  ├─ Time to live: 64      ← TTL VALUE
  ├─ Protocol: TCP (6)
  ├─ Source: 192.168.1.100
  └─ Destination: 93.184.216.34

▼ Transmission Control Protocol, Src Port: 54321, Dst Port: 80
  ├─ Source Port: 54321
  ├─ Destination Port: 80
  ├─ Sequence number: 0
  ├─ Flags: 0x002 (SYN)
  └─ Window size: 64240

▼ Hypertext Transfer Protocol
  ├─ GET / HTTP/1.1\r\n          ← PAYLOAD
  ├─ Host: example.com\r\n
  └─ User-Agent: curl/7.68.0\r\n
```

#### Understanding TTL (Time To Live)

**What is TTL?**
- A counter that decreases by 1 at each router hop
- Prevents packets from looping infinitely
- Helps identify the operating system

**Common TTL Values:**

| Operating System | Default TTL |
|-----------------|-------------|
| Linux/Unix      | 64          |
| Windows         | 128         |
| Cisco IOS       | 255         |

**Example Filter to Find Low TTL:**
```
ip.ttl < 10
```

#### Analyzing Payload

The payload is the actual data being transmitted.

**Example: Finding Passwords in HTTP**

```
Display Filter: http.request.method == "POST"
```

Then look in the Packet Bytes pane for cleartext data:
```
username=admin&password=P@ssw0rd123
```

---

### Packet Navigation

#### Finding Packets

**Method 1: Edit → Find Packet (Ctrl+F)**

Options:
- **Display filter**: Use filter syntax
- **Hex value**: Search for hex pattern
- **String**: Search for ASCII/UTF-8 text
- **Regular Expression**: Advanced pattern matching

**Example Searches:**

```plaintext
1. Find all DNS queries:
   Display Filter → dns.qry.name

2. Find hex pattern (e.g., malware signature):
   Hex value → 4d5a90

3. Find string "password":
   String → password
```

#### Following Streams

Reconstructs the entire conversation between two endpoints.

**TCP Stream Example:**

1. Right-click on any TCP packet
2. Select **Follow → TCP Stream**
3. View the entire conversation in a new window

**Color Coding:**
- 🔴 Red: Client → Server
- 🔵 Blue: Server → Client

**Example: HTTP Login Capture**

```
Filter: http
Right-click → Follow → TCP Stream
```

Result shows:
```http
GET /login.php HTTP/1.1
Host: vulnerable-site.com
User-Agent: Mozilla/5.0

HTTP/1.1 200 OK
Content-Type: text/html

<html>
  <form action="/auth.php" method="POST">
    <input name="user" />
    <input name="pass" type="password" />
  </form>
</html>
```

**Other Stream Types:**
- **UDP Stream**: For UDP conversations
- **TLS Stream**: For encrypted HTTPS (if keys available)
- **HTTP Stream**: Shows HTTP objects

#### Quick Navigation

**Keyboard Shortcuts:**

| Action | Shortcut |
|--------|----------|
| Next packet | ↓ or Ctrl+↓ |
| Previous packet | ↑ or Ctrl+↑ |
| First packet | Home or Ctrl+Home |
| Last packet | End or Ctrl+End |
| Go to packet # | Ctrl+G |

#### Packet Comments

Add notes to specific packets for documentation.

**Adding Comments:**

1. Right-click packet → **Packet Comment**
2. Type your note
3. Save the file (comments are saved in .pcapng format)

**Example Use Case:**
```
Packet #42: "Suspicious connection to known C2 server"
Packet #156: "Credential theft attempt - username 'admin'"
Packet #892: "Data exfiltration detected - 50MB transfer"
```

---

### Packet Filtering

Filtering is crucial for analyzing large captures efficiently.

#### Display Filters vs Capture Filters

**Display Filters** (used during analysis):
```
ip.addr == 192.168.1.100
```

**Capture Filters** (used before capturing):
```
host 192.168.1.100
```

#### Basic Display Filters

**By Protocol:**
```
http
dns
tcp
udp
icmp
arp
```

**By IP Address:**
```
ip.addr == 192.168.1.100           # Either source or destination
ip.src == 192.168.1.100            # Source only
ip.dst == 192.168.1.100            # Destination only
```

**By Port:**
```
tcp.port == 80                     # Either source or destination
tcp.srcport == 54321               # Source port
tcp.dstport == 443                 # Destination port
```

#### Right-Click Filtering

Wireshark makes filtering easy with context menus.

**Example Workflow:**

1. Click on a packet
2. Expand the protocol tree
3. Right-click on any field
4. Choose from options:
   - **Apply as Filter → Selected**: Shows only matching packets
   - **Apply as Filter → Not Selected**: Excludes matching packets
   - **Prepare as Filter → And Selected**: Adds to existing filter with AND
   - **Prepare as Filter → Or Selected**: Adds to existing filter with OR

**Example: Filter by MAC Address**

```
Right-click on Ethernet source address → Apply as Filter → Selected
Result: eth.src == 00:11:22:33:44:55
```

#### Coloring Rules

Visual identification of packet types.

**View Coloring Rules:**
```
View → Coloring Rules
```

**Default Colors:**

| Color | Meaning |
|-------|---------|
| Light Purple | TCP |
| Light Blue | UDP |
| Black | Packets with errors |
| Light Green | HTTP |
| Yellow | Windows-specific |
| Dark Gray | TCP retransmission |

**Creating Custom Rules:**

```
1. View → Coloring Rules → + (Add)
2. Name: "Suspicious Ports"
3. Filter: tcp.port == 4444 || tcp.port == 31337
4. Choose red background
5. OK
```

**Example: Highlight DNS Traffic**

```
Name: DNS Traffic
Filter: dns
Foreground: Black
Background: Light Yellow
```

---

## 🔧 Part 2: Packet Operations

### Statistics Overview

Wireshark provides powerful statistical analysis tools.

#### Summary Statistics

```
Statistics → Capture File Properties
```

**Key Metrics:**
- Total packets captured
- Packets per second
- Average packet size
- Total bytes transferred
- Capture duration

#### Conversations

Shows all conversations between endpoints.

```
Statistics → Conversations
```

**Tabs Available:**
- **Ethernet**: MAC-level conversations
- **IPv4/IPv6**: IP-level conversations
- **TCP**: TCP connections
- **UDP**: UDP conversations

**Example Analysis:**

```
IPv4 Tab sorted by Bytes:
Address A          Address B          Packets  Bytes    Duration
192.168.1.100  →  93.184.216.34      1543     2.1 MB   120.5 s
192.168.1.100  →  8.8.8.8            43       3.2 KB   5.2 s
```

This reveals:
- Largest data transfer was to 93.184.216.34
- Likely file download or upload
- DNS queries to 8.8.8.8

#### Endpoints

Shows traffic per individual endpoint.

```
Statistics → Endpoints
```

**Use Cases:**
- Identify most active hosts
- Find bandwidth hogs
- Detect scanning activity (many packets to one host)

---

### Protocol Details

#### Protocol Hierarchy

```
Statistics → Protocol Hierarchy
```

**Example Output:**

```
Frame                          Packets: 1000    Bytes: 1.2 MB
├─ Ethernet                    100%             100%
│  ├─ IPv4                     95%              94%
│  │  ├─ TCP                   70%              85%
│  │  │  ├─ HTTP               40%              60%
│  │  │  ├─ TLS                15%              20%
│  │  │  └─ SSH                15%              5%
│  │  ├─ UDP                   20%              8%
│  │  │  ├─ DNS                15%              5%
│  │  │  └─ QUIC               5%               3%
│  │  └─ ICMP                  5%               1%
│  └─ ARP                      5%               6%
```

**Analysis Insights:**
- 40% HTTP traffic suggests unencrypted web browsing
- 15% TLS is HTTPS traffic
- 15% DNS is normal
- 5% ARP is typical for local network

#### Protocol-Specific Statistics

**HTTP Statistics:**
```
Statistics → HTTP → Requests
```

Shows all HTTP requests with:
- Request method (GET, POST, etc.)
- Host
- URI
- Response code

**DNS Statistics:**
```
Statistics → DNS
```

Shows:
- Query/response distribution
- Most queried domains
- Response time analysis

---

### Filtering Principles

#### The Filtering Mindset

**Ask These Questions:**

1. **What am I looking for?** (Protocol, host, suspicious activity)
2. **What time frame?** (Recent activity, specific time)
3. **What direction?** (Inbound, outbound, specific endpoints)
4. **What pattern?** (Normal vs abnormal)

#### Building Complex Filters

**Start Broad, Then Narrow:**

```
Step 1: http
Step 2: http && ip.addr == 192.168.1.100
Step 3: http && ip.addr == 192.168.1.100 && http.request.method == "POST"
```

#### Filter Operators

**Comparison Operators:**

```
==    Equal to
!=    Not equal to
>     Greater than
<     Less than
>=    Greater than or equal
<=    Less than or equal
```

**Logical Operators:**

```
&&    AND (both conditions must be true)
||    OR (either condition must be true)
!     NOT (negation)
```

**Examples:**

```
# Large packets only
frame.len > 1000

# Exclude local traffic
!(ip.addr == 192.168.1.0/24)

# HTTP or HTTPS
tcp.port == 80 || tcp.port == 443
```

---

### Protocol Filters

#### Common Protocol Filters

**Network Layer:**

```
# IPv4 traffic only
ip

# Specific IP subnet
ip.addr == 10.0.0.0/8

# Broadcast traffic
eth.dst == ff:ff:ff:ff:ff:ff

# Multicast
ip.dst == 224.0.0.0/4
```

**Transport Layer:**

```
# All TCP traffic
tcp

# TCP SYN packets (connection attempts)
tcp.flags.syn == 1 && tcp.flags.ack == 0

# TCP resets
tcp.flags.reset == 1

# All UDP traffic
udp

# ICMP (ping)
icmp
```

**Application Layer:**

```
# DNS queries only
dns.flags.response == 0

# DNS responses only
dns.flags.response == 1

# HTTP GET requests
http.request.method == "GET"

# HTTP 404 errors
http.response.code == 404

# TLS handshakes
tls.handshake.type == 1
```

#### Port-Based Filters

```
# Common services
tcp.port == 80       # HTTP
tcp.port == 443      # HTTPS
tcp.port == 22       # SSH
tcp.port == 21       # FTP
tcp.port == 25       # SMTP
tcp.port == 3389     # RDP
udp.port == 53       # DNS
udp.port == 67       # DHCP
```

**Port Ranges:**

```
# Ephemeral ports
tcp.srcport >= 49152 && tcp.srcport <= 65535

# Well-known ports
tcp.dstport <= 1023
```

---

### Advanced Filtering

#### Using Contains

Search for strings in packet data:

```
# Find packets containing "password"
frame contains "password"

# Case-insensitive (convert to lowercase first in your mind)
tcp contains "admin"

# HTTP headers containing specific user agent
http.user_agent contains "Mozilla"
```

#### Using Matches (Regex)

```
# Match IP addresses ending in .1
ip.addr matches "\\d+\\.\\d+\\.\\d+\\.1$"

# Match suspicious User-Agents
http.user_agent matches "(?i)(bot|crawler|scanner)"
```

#### Combining Multiple Conditions

**Example 1: Detect Potential SQL Injection**

```
http.request.uri contains "SELECT" || 
http.request.uri contains "UNION" || 
http.request.uri contains "OR 1=1"
```

**Example 2: Find Large File Transfers**

```
http && frame.len > 1400 && http.content_length > 1000000
```

**Example 3: Suspicious Port Activity**

```
(tcp.port == 4444 || tcp.port == 5555 || tcp.port == 31337) && 
ip.dst != 192.168.1.0/24
```

#### Macro Filters

Save common filters for reuse:

```
Right-click filter bar → Display Filter Expression

Create macro named "suspicious_traffic":
tcp.port == 4444 || tcp.port == 1337 || tcp.flags.reset == 1
```

---

## 🔍 Part 3: Traffic Analysis

### Introduction to Traffic Analysis

Network traffic analysis involves:
1. **Baseline** - Understanding normal traffic patterns
2. **Anomaly Detection** - Identifying deviations
3. **Investigation** - Deep diving into suspicious activity
4. **Documentation** - Recording findings

---

### Nmap Scan Detection

#### TCP SYN Scan Detection

**Characteristics:**
- Many SYN packets to different ports
- No completed three-way handshakes
- Sequential or random port targeting

**Filter to Detect:**

```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

**Analysis Steps:**

1. Apply filter
2. Check `Statistics → Conversations`
3. Look for one source connecting to many ports

**Example Output:**

```
Source: 192.168.1.50
Destination: 192.168.1.100
Ports: 20, 21, 22, 23, 25, 80, 110, 143, 443, 445, 3389...
Pattern: Sequential port scanning detected
```

**Identifying Scan Type:**

```
# TCP Connect Scan (full handshake)
tcp.flags.syn == 1 && tcp.flags.ack == 1

# NULL Scan (no flags)
tcp.flags == 0

# FIN Scan
tcp.flags.fin == 1 && tcp.flags.syn == 0 && tcp.flags.ack == 0

# Xmas Scan (FIN, PSH, URG set)
tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1
```

#### UDP Scan Detection

```
udp && icmp.type == 3 && icmp.code == 3
```

**Interpretation:**
- Multiple ICMP "Port Unreachable" messages
- Indicates UDP port scanning

---

### ARP Poisoning MITM

#### What is ARP Poisoning?

Attacker sends fake ARP replies to associate their MAC address with another host's IP address.

#### Detection Techniques

**Filter 1: Duplicate IP Addresses**

```
arp.duplicate-address-detected
```

**Filter 2: Gratuitous ARP**

```
arp.opcode == 2 && eth.src == arp.src.hw_mac
```

**Filter 3: ARP Rate Analysis**

```
arp
```

Then check `Statistics → Conversations → Ethernet`

**Red Flags:**
- Same IP with multiple MAC addresses
- Excessive ARP replies from one host
- ARP replies without requests

**Example Attack Pattern:**

```
Time     Source MAC         Source IP      Dest MAC           Dest IP
10:00:01 aa:bb:cc:dd:ee:ff  192.168.1.1   ff:ff:ff:ff:ff:ff  192.168.1.100
10:00:01 aa:bb:cc:dd:ee:ff  192.168.1.100 ff:ff:ff:ff:ff:ff  192.168.1.1
```

Attacker (aa:bb:cc:dd:ee:ff) claims to be both the gateway (.1) and victim (.100).

---

### Host Identification

#### DHCP Analysis

```
bootp
```

or

```
dhcp
```

**Information Revealed:**
- Client hostname
- MAC address
- Requested IP
- Vendor information

**Example DHCP Discover:**

```
▼ Bootstrap Protocol (Discover)
  ├─ Client MAC address: 00:11:22:33:44:55
  ├─ Client IP address: 0.0.0.0
  ├─ Your (client) IP address: 0.0.0.0
  ├─ Option: Hostname = "JOHNS-LAPTOP"
  ├─ Option: Vendor class = "MSFT 5.0"
  └─ Option: Requested IP = 192.168.1.105
```

#### NetBIOS Name Service

```
nbns
```

**Reveals:**
- Computer names
- Workgroup/Domain names
- Services running

#### Kerberos Analysis

```
kerberos
```

**Information:**
- Domain names
- Usernames
- Service principal names (SPNs)
- Authentication attempts

**Example Filter for Failed Logins:**

```
kerberos.error_code == 6
```

---

### Tunneling Traffic

#### DNS Tunneling Detection

**Characteristics:**
- Unusually long DNS queries
- High volume of DNS traffic
- Subdomains with random-looking strings

**Detection Filters:**

```
# Queries longer than 50 characters
dns.qry.name.len > 50

# TXT record queries (often used for tunneling)
dns.qry.type == 16

# Excessive queries to same domain
dns && dns.flags.response == 0
```

**Example Suspicious 
# Queries longer than 50 characters
dns.qry.name.len > 50

# TXT record queries (often used for tunneling)
dns.qry.type == 16

# Excessive queries to same domain
dns && dns.flags.response == 0
Example Suspicious DNS:
Query: a3d5f8b2c1e9.f4a7b3d2e1c5.f7e8d9c3b2a1.evil-domain.com
Type: TXT
Length: 92 characters
ICMP Tunneling Detection
Characteristics:
ICMP packets with unusual payload sizes
Regular ICMP traffic (not just sporadic pings)
Non-standard payload data
Detection Filter:
# ICMP with large data section
icmp && data.len > 48

# Frequent ICMP
icmp
Then check Statistics → IO Graphs for patterns.
Example Legitimate vs Tunneled:
Legitimate ping:
- Size: 64 bytes
- Data: Repeating pattern (abcd...)

Tunneled:
- Size: 1400 bytes
- Data: Random or encoded content
Protocol Analysis
FTP Analysis
ftp
What to Look For:
# FTP Authentication
ftp.request.command == "USER" || ftp.request.command == "PASS"

# File operations
ftp.request.command == "RETR" || ftp.request.command == "STOR"
Following FTP Session:
Filter: ftp
Find connection
Right-click → Follow → TCP Stream
Example Output:
220 FTP Server Ready
USER admin
331 Password required
PASS supersecret123
230 Login successful
CWD /secret-files
250 Directory changed
RETR passwords.txt
150 Opening data connection
226 Transfer complete
FTP-DATA Channel:
ftp-data
This shows the actual file contents being transferred.
HTTP Analysis
http
Key Request Methods:
http.request.method == "GET"     # Retrieving data
http.request.method == "POST"    # Submitting data
http.request.method == "PUT"     # Uploading files
http.request.method == "DELETE"  # Removing resources
Response Analysis:
# Successful responses
http.response.code == 200

# Redirects
http.response.code >= 300 && http.response.code < 400

# Client errors
http.response.code >= 400 && http.response.code < 500

# Server errors
http.response.code >= 500
Export HTTP Objects:
File → Export Objects → HTTP
This lets you save files transferred over HTTP.
Suspicious HTTP Patterns:
# Potential SQL injection
http.request.uri contains "' OR '1'='1"

# Directory traversal
http.request.uri contains "../"

# Command injection
http.request.uri contains "|" || http.request.uri contains ";"
Decrypting HTTPS SSL TLS
Prerequisites:
Have the private key (server.key), OR
Have the pre-master secret (from browser)
Method 1: Using Private Key
Get the server's private key file
In Wireshark:
Edit → Preferences → Protocols → TLS

Click "Edit" next to "RSA keys list"
Add entry:
IP Address: 192.168.1.50
Port: 443
Protocol: http
Key File: /path/to/server.key
Method 2: Using Browser Pre-Master Secret
Set environment variable before starting browser:
# Linux/Mac
export SSLKEYLOGFILE=~/sslkeys.log
firefox &

# Windows (PowerShell)
$env:SSLKEYLOGFILE="C:\Users\YourName\sslkeys.log"
Start-Process firefox
In Wireshark:
Edit → Preferences → Protocols → TLS
(Pre)-Master-Secret log filename: ~/sslkeys.log
Capture traffic and browse HTTPS sites
Wireshark automatically decrypts matching sessions
Verifying Decryption:
After setup, you should see:
# Instead of "TLS"
http

# Decrypted content visible
HTTP/1.1 200 OK
Content-Type: text/html

<html>
  <body>Secret data revealed!</body>
</html>
Credential Hunting
Finding Cleartext Credentials
Basic String Search:
frame contains "password" || 
frame contains "passwd" || 
frame contains "pwd"
Protocol-Specific:
# HTTP POST (login forms)
http.request.method == "POST"

# FTP
ftp.request.command == "USER" || ftp.request.command == "PASS"

# Telnet
telnet

# SMTP AUTH
smtp.req.command == "AUTH"
Advanced Credential Hunting:
# Base64 encoded (HTTP Auth)
http.authbasic

# NTLM
ntlmssp

# Look in packet bytes for:
- "username="
- "user="
- "login="
- "email="
Example: HTTP Basic Auth
Filter:
http.authorization
Packet details:
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
Decode Base64:
echo "YWRtaW46cGFzc3dvcmQ=" | base64 -d
# Output: admin:password
Producing Actionable Results
Extracting Indicators of Compromise IOCs
IP Addresses:
1. Apply relevant filters
2. Statistics → Endpoints → IPv4
3. Export suspicious IPs
Domains:
dns
Statistics → DNS
Export query names
File Hashes:
1. File → Export Objects → HTTP
2. Save suspicious files
3. Generate hashes:

# Linux/Mac
md5sum file.exe
sha256sum file.exe

# Windows
certutil -hashfile file.exe MD5
certutil -hashfile file.exe SHA256
Creating an Analysis Report
Template Structure:
# Network Traffic Analysis Report

## Executive Summary
Brief overview of findings and risk level.

## Analysis Details

### Timeline
- Capture Start: 2025-11-17 10:00:00 UTC
- Capture End: 2025-11-17 11:30:00 UTC
- Duration: 1.5 hours

### Key Findings

#### 1. Nmap Scan Detected
- Source IP: 10.0.50.25
- Target IP: 192.168.1.100
- Ports Scanned: 1-1000
- Timestamp: 10:15:32 UTC
- Evidence: Packet #142-1850

#### 2. Credential Theft
- Protocol: HTTP
- Credentials: username=admin,
- 
password=P@ssw0rd123
- Target Site: http://internal-portal.company.com/login.php
- Source IP: 192.168.1.45
- Timestamp: 10:42:18 UTC
- Evidence: Packet #3421

#### 3. Data Exfiltration via DNS Tunneling
- Suspicious Domain: *.evilc2server.com
- Volume: 1,247 DNS queries in 10 minutes
- Average Query Length: 87 characters
- Source IP: 192.168.1.78
- Timestamp: 11:05:00 - 11:15:00 UTC
- Evidence: Packets #5200-6447

### Network Statistics
- Total Packets: 15,432
- Total Data: 12.4 MB
- Unique Hosts: 47
- Protocols: HTTP (45%), HTTPS (30%), DNS (15%), Other (10%)

## Indicators of Compromise (IOCs)

### IP Addresses
```
10.0.50.25          # Scanning source
203.0.113.66        # C2 server
198.51.100.42       # Malicious file download
```

### Domains
```
evilc2server.com
malware-drop.net
phishing-site.com
```

### File Hashes
```
MD5: 5d41402abc4b2a76b9719d911017c592
SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706...
Filename: malicious.exe
```

### URLs
```
http://internal-portal.company.com/login.php
http://malware-drop.net/payload.exe
http://203.0.113.66:8080/data
```

## Recommendations

### Immediate Actions
1. Block IP addresses listed in IOCs
2. Reset credentials for user at 192.168.1.45
3. Isolate host 192.168.1.78 (potential infection)
4. Block DNS queries to evilc2server.com

### Short-term Actions
1. Deploy IDS/IPS rules for detected attack patterns
2. Implement DNS filtering
3. Force password reset for all users accessing internal-portal
4. Conduct malware scan on 192.168.1.78

### Long-term Actions
1. Implement HTTPS for all internal applications
2. Deploy network segmentation
3. Enhance DNS monitoring and logging
4. Conduct security awareness training

## Conclusion
Multiple security incidents detected including reconnaissance, 
credential theft, and potential data exfiltration. Immediate 
response required to contain threats.

## Appendices

### A. Wireshark Filters Used
```
# Scan detection
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Credential hunting
http.request.method == "POST" && frame contains "password"

# DNS tunneling
dns.qry.name.len > 50
```

### B. Evidence Files
- capture.pcapng (original capture)
- suspicious_traffic.pcapng (filtered capture)
- exported_files/ (directory with extracted files)

---
Report Generated: 2025-11-17 12:00:00 UTC
Analyst: [Your Name]
Tools: Wireshark 4.0.6
```

---

## 🎯 Best Practices

### Capture Best Practices

#### 1. Use Capture Filters When Possible

Reduces file size and improves performance.

```bash
# Capture only HTTP and HTTPS
tcp port 80 or tcp port 443

# Capture specific host
host 192.168.1.100

# Exclude local broadcast
not broadcast and not multicast
```

#### 2. Name Captures Descriptively

```
capture_2025-11-17_incident_response_web_server.pcapng
capture_2025-11-17_baseline_normal_traffic.pcapng
```

#### 3. Split Large Captures

```bash
# Split by size (100MB per file)
tshark -i eth0 -w capture.pcapng -b filesize:100000

# Split by time (3600 seconds = 1 hour)
tshark -i eth0 -w capture.pcapng -b duration:3600

# Ring buffer (keep only last 5 files)
tshark -i eth0 -w capture.pcapng -b filesize:100000 -b files:5
```

---

### Analysis Best Practices

#### 1. Start with Statistics

Always begin analysis with:
```
Statistics → Capture File Properties
Statistics → Protocol Hierarchy
Statistics → Conversations
```

#### 2. Use Time Display Formats

```
View → Time Display Format
```

Options:
- **Seconds Since Beginning of Capture**: Good for timeline analysis
- **Date and Time of Day**: Good for correlation with logs
- **Seconds Since Previous Displayed Packet**: Good for timing analysis

#### 3. Create Custom Columns

Right-click column header → Column Preferences → Add

**Useful Custom Columns:**

| Title | Type | Field |
|-------|------|-------|
| Source Port | Custom | tcp.srcport |
| Dest Port | Custom | tcp.dstport |
| HTTP Host | Custom | http.host |
| DNS Query | Custom | dns.qry.name |
| TLS SNI | Custom | tls.handshake.extensions_server_name |

#### 4. Use Profiles for Different Tasks

```
Edit → Configuration Profiles
```

**Create Profiles:**
- **Web Analysis**: HTTP/HTTPS columns, colorization
- **Malware Analysis**: Suspicious ports highlighted, DNS tracking
- **Baseline Monitoring**: Statistics-focused view

---

### Display Filter Examples Cheat Sheet

```bash
# ============================================
# BASIC FILTERS
# ============================================

# Show only specific protocol
http
dns
tcp
udp
arp
icmp

# ============================================
# IP FILTERING
# ============================================

# Specific IP (source or destination)
ip.addr == 192.168.1.100

# Specific source IP
ip.src == 192.168.1.100

# Specific destination IP
ip.dst == 192.168.1.100

# Subnet
ip.addr == 192.168.1.0/24

# Exclude IP
!(ip.addr == 192.168.1.100)

# Private IP ranges only
ip.addr == 10.0.0.0/8 || ip.addr == 172.16.0.0/12 || ip.addr == 192.168.0.0/16

# ============================================
# PORT FILTERING
# ============================================

# Specific port (source or destination)
tcp.port == 80
udp.port == 53

# Specific source port
tcp.srcport == 54321

# Specific destination port
tcp.dstport == 443

# Port range
tcp.port >= 1024 && tcp.port <= 49151

# Multiple specific ports
tcp.port == 80 || tcp.port == 443 || tcp.port == 8080

# ============================================
# TCP FLAGS
# ============================================

# SYN packets
tcp.flags.syn == 1

# SYN-ACK packets
tcp.flags.syn == 1 && tcp.flags.ack == 1

# RST packets
tcp.flags.reset == 1

# FIN packets
tcp.flags.fin == 1

# PSH-ACK (data transfer)
tcp.flags.push == 1 && tcp.flags.ack == 1

# Only SYN, no ACK (new connections)
tcp.flags.syn == 1 && tcp.flags.ack == 0

# ============================================
# HTTP FILTERING
# ============================================

# HTTP requests only
http.request

# HTTP responses only
http.response

# Specific HTTP method
http.request.method == "GET"
http.request.method == "POST"
http.request.method == "PUT"

# HTTP status codes
http.response.code == 200
http.response.code == 404
http.response.code == 500

# HTTP status code ranges
http.response.code >= 400 && http.response.code < 500  # Client errors
http.response.code >= 500  # Server errors

# Specific host
http.host == "example.com"

# URI contains string
http.request.uri contains "/admin"

# User-Agent
http.user_agent contains "curl"

# HTTP Basic Auth
http.authbasic

# ============================================
# DNS FILTERING
# ============================================

# DNS queries only
dns.flags.response == 0

# DNS responses only
dns.flags.response == 1

# Specific query name
dns.qry.name == "example.com"

# Query name contains
dns.qry.name contains "malware"

# Specific query type
dns.qry.type == 1   # A record
dns.qry.type == 28  # AAAA record
dns.qry.type == 15  # MX record
dns.qry.type == 16  # TXT record

# Long DNS queries (potential tunneling)
dns.qry.name.len > 50

# DNS errors
dns.flags.rcode != 0

# ============================================
# TLS/SSL FILTERING
# ============================================

# All TLS traffic
tls

# TLS handshake
tls.handshake.type == 1  # Client Hello
tls.handshake.type == 2  # Server Hello

# Server Name Indication (SNI)
tls.handshake.extensions_server_name == "example.com"

# TLS alerts
tls.alert_message

# ============================================
# ADVANCED FILTERS
# ============================================

# Large packets
frame.len > 1500

# Small packets (potential scan)
frame.len < 60

# Broadcast
eth.dst == ff:ff:ff:ff:ff:ff

# Multicast
eth.dst[0] & 1

# Contains specific string in payload
frame contains "password"
tcp contains "admin"

# Regex matching
http.user_agent matches "(?i)(bot|crawler)"

# Time-based
frame.time >= "2025-11-17 10:00:00" && frame.time <= "2025-11-17 11:00:00"

# Retransmissions
tcp.analysis.retransmission

# Duplicate ACKs
tcp.analysis.duplicate_ack

# Zero Window (flow control issues)
tcp.window_size == 0

# ============================================
# SECURITY-FOCUSED FILTERS
# ============================================

# Potential port scans
tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.window_size <= 1024

# Suspicious ports (common backdoors)
tcp.port == 4444 || tcp.port == 5555 || tcp.port == 31337 || tcp.port == 1337

# ARP spoofing indicators
arp.duplicate-address-detected || arp.duplicate-address-frame

# ICMP tunneling (large payloads)
icmp && data.len > 48

# SQL injection patterns
http.request.uri contains "SELECT" || 
http.request.uri contains "UNION" || 
http.request.uri contains "' OR 1=1"

# Directory traversal
http.request.uri contains "../"

# Command injection
http.request.uri contains ";" || http.request.uri contains "|"

# SMB null sessions
smb.path == "\\\\IPC$"

# Suspicious TLS versions (outdated)
tls.handshake.version == 0x0300  # SSL 3.0
tls.handshake.version == 0x0301  # TLS 1.0

# ============================================
# TROUBLESHOOTING FILTERS
# ============================================

# Errors and warnings
expert.severity == "Error"
expert.severity == "Warn"

# Connection problems
tcp.analysis.flags

# Out of order packets
tcp.analysis.out_of_order

# Lost segments
tcp.analysis.lost_segment

# Fast retransmissions
tcp.analysis.fast_retransmission

# ============================================
# COMBINING FILTERS
# ============================================

# Complex example: Find suspicious web traffic from internal to external
http && 
ip.src == 192.168.0.0/16 && 
!(ip.dst == 192.168.0.0/16) && 
(http.request.uri contains "cmd" || http.request.uri contains "exec")

# Lateral movement detection
(tcp.port == 445 || tcp.port == 139 || tcp.port == 3389) && 
ip.src == 192.168.0.0/16 && 
ip.dst == 192.168.0.0/16 && 
!(ip.dst == 192.168.1.1)

# Data exfiltration indicators
(http.request.method == "POST" || http.request.method == "PUT") && 
http.content_length > 1000000 && 
!(ip.dst == 192.168.0.0/16)
```

---

### Performance Optimization

#### For Large Capture Files

1. **Use Display Filters, Not Capture Filters** (for already captured data)
2. **Disable Protocol Dissectors** you don't need:
   ```
   Analyze → Enabled Protocols → Uncheck unused protocols
   ```

3. **Use tshark for Command-Line Analysis**:
   ```bash
   # Extract specific packets
   tshark -r large.pcapng -Y "http" -w filtered.pcapng
   
   # Get statistics
   tshark -r large.pcapng -q -z io,phs
   
   # Extract specific fields
   tshark -r large.pcapng -T fields -e ip.src -e ip.dst -e tcp.port
   ```

4. **Split Files**:
   ```bash
   # Split by packet count (10000 packets per file)
   editcap -c 10000 large.pcapng split.pcapng
   ```

---

## 🛠️ Advanced Techniques

### Using TShark for Automation

#### Basic TShark Commands

```bash
# Capture to file
tshark -i eth0 -w capture.pcapng

# Read and display
tshark -r capture.pcapng

# Apply display filter
tshark -r capture.pcapng -Y "http"

# Count packets by protocol
tshark -r capture.pcapng -q -z io,phs

# Extract HTTP hosts
tshark -r capture.pcapng -Y "http.request" -T fields -e http.host | sort | uniq

# Extract credentials from HTTP
tshark -r capture.pcapng -Y "http.request.method == POST" -T fields -e text | grep -i "password"
```

#### Automated Analysis Script

```bash
#!/bin/bash
# automated_analysis.sh

PCAP_FILE=$1
OUTPUT_DIR="analysis_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"

echo "[+] Starting automated analysis of $PCAP_FILE"

# Basic statistics
echo "[+] Gathering basic statistics..."
tshark -r "$PCAP_FILE" -q -z io,phs > "$OUTPUT_DIR/protocol_hierarchy.txt"

# Extract unique IPs
echo "[+] Extracting IP addresses..."
tshark -r "$PCAP_FILE" -T fields -e ip.src -e ip.dst | \
  tr '\t' '\n' | sort | uniq > "$OUTPUT_DIR/unique_ips.txt"

# Extract HTTP hosts
echo "[+] Extracting HTTP hosts..."
tshark -r "$PCAP_FILE" -Y "http.request" -T fields -e http.host | \
  sort | uniq -c | sort -rn > "$OUTPUT_DIR/http_hosts.txt"

# Extract DNS queries
echo "[+] Extracting DNS queries..."
tshark -r "$PCAP_FILE" -Y "dns.flags.response == 0" -T fields -e dns.qry.name | \
  sort | uniq -c | sort -rn > "$OUTPUT_DIR/dns_queries.txt"

# Find potential scans
echo "[+] Detecting potential scans..."
tshark -r "$PCAP_FILE" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport | \
  awk '{count[$1]++} END {for (ip in count) if (count[ip] > 50) print ip, count[ip]}' \
  > "$OUTPUT_DIR/potential_scans.txt"

# Extract suspicious long DNS queries
echo "[+] Finding suspicious DNS queries..."
tshark -r "$PCAP_FILE" -Y "dns.qry.name.len > 50" \
  -T fields -e dns.qry.name > "$OUTPUT_DIR/suspicious_dns.txt"

# Find HTTP POST requests
echo "[+] Extracting HTTP POST requests..."
tshark -r "$PCAP_FILE" -Y "http.request.method == POST" \
  -T fields -e ip.src -e http.host -e http.request.uri \
  > "$OUTPUT_DIR/http_posts.txt"

echo "[+] Analysis complete! Results in $OUTPUT_DIR/"
```

**Usage:**
```bash
chmod +x automated_analysis.sh
./automated_analysis.sh capture.pcapng
```

---

### Creating Custom Dissectors

For proprietary protocols, you can write Lua dissectors.

**Example: Simple Protocol Dissector**

```lua
-- custom_protocol.lua
-- Simple example: Protocol that has 2-byte type, 2-byte length, then data

custom_proto = Proto("customproto", "Custom Protocol")

local f_type = ProtoField.uint16("customproto.type", "Type", base.HEX)
local f_length = ProtoField.uint16("customproto.length", "Length", base.DEC)
local f_data = ProtoField.bytes("customproto.data", "Data")

custom_proto.fields = {f_type, f_length, f_data}

function custom_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "CUSTOM"
    
    local subtree = tree:add(custom_proto, buffer())
    
    -- Parse fields
    subtree:add(f_type, buffer(0, 2))
    subtree:add(f_length, buffer(2, 2))
    
    local length = buffer(2, 2):uint()
    if length > 0 then
        subtree:add(f_data, buffer(4, length))
    end
end

-- Register for TCP port 9999
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(9999, custom_proto)
```

**Loading Custom Dissector:**
```
Analyze → Reload Lua Plugins
```

Or place in:
- Windows: `%APPDATA%\Wireshark\plugins\`
- Linux: `~/.local/lib/wireshark/plugins/`

---

### Integration with Security Tools

#### Exporting to Snort/Suricata Rules

After identifying malicious traffic:

**Example Snort Rule:**
```
alert tcp any any -> any 4444 (
    msg:"Potential backdoor connection to port 4444";
    flags:S;
    sid:1000001;
    rev:1;
)
```

#### Exporting IOCs to MISP

```bash
# Extract IPs and create MISP event
tshark -r malware.pcapng -Y "ip.dst == 203.0.113.66" \
  -T fields -e ip.dst | sort | uniq > iocs.txt

# Then import to MISP via web interface or API
```

#### Converting to Zeek/Bro Logs

```bash
# Use Zeek to generate logs from pcap
zeek -r capture.pcapng

# Generates: conn.log, http.log, dns.log, etc.
```

---

## 📚 Resources

### Official Documentation

- **Wireshark User Guide**: https://www.wireshark.org/docs/wsug_html_chunked/
- **Wireshark Wiki**: https://wiki.wireshark.org/
- **Display Filter Reference**: https://www.wireshark.org/docs/dfref/

### Sample Captures

- **Wireshark Sample Captures**: https://wiki.wireshark.org/SampleCaptures
- **Malware-Traffic-Analysis.net**: https://malware-traffic-analysis.net/
- **PacketLife**: http://packetlife.net/captures/

### Learning Resources

- **Wireshark Network Analysis** (Book by Laura Chappell)
- **Practical Packet Analysis** (Book by Chris Sanders)
- **SANS SEC503**: Intrusion Detection In-Depth

### Community

- **Wireshark Q&A**: https://ask.wireshark.org/
- **SharkFest**: Annual Wireshark conference
- **r/Wireshark**: Reddit community

---

## 🎓 Practice Exercises

### Exercise 1: Basic Analysis

**Objective:** Analyze HTTP traffic

1. Download sample: https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=http.cap
2. Tasks:
   - Find all HTTP requests
   - Identify the server responding
   - Export HTTP objects
   - Follow TCP streams

**Solution:**
```
Filter: http
Statistics → HTTP → Requests
File → Export Objects → HTTP
Right-click packet → Follow → TCP Stream
```

---

### Exercise 2: Detecting Port Scans

**Objective:** Identify scanning activity

**Scenario:** Given a capture file with a port scan

1. Filter for SYN packets: `tcp.flags.syn == 1 && tcp.flags.ack == 0`
2. Check Statistics → Conversations → TCP
3. Identify source performing scan
4. Determine scan type and target ports

---

### Exercise 3: Credential Extraction

**Objective:** Find cleartext credentials

**Tasks:**
1. Filter for HTTP POST: `http.request.method == "POST"`
2. Follow TCP streams
3. Look for form data containing credentials
4. Extract username and password

**Bonus:** Try with FTP protocol

---

### Exercise 4: Malware Traffic Analysis

**Objective:** Analyze potential infection

Download a malware pcap from malware-traffic-analysis.net

**Analysis Steps:**
1. Identify infected host (unusual traffic patterns)
2. Find initial infection vector
3. Identify C2 communications
4. Extract IOCs (IPs, domains, file hashes)
5. Document timeline of events
6. Create report with findings

---

## 🔐 Security Considerations

### Handling Sensitive Captures

1. **Sanitize Before Sharing:**
   ```bash
   # Remove sensitive IPs
   tcprewrite --infile=capture.pcap --outfile=sanitized.pcap \
     --pnat=192.168.1.0/24:10.0.0.0/24
   ```

2. **Encrypt Storage:**
   ```bash
   # Encrypt with GPG
   gpg -c sensitive-capture.pcapng
   
   # Decrypt
   gpg sensitive-capture.pcapng.gpg
   ```

3. **Secure Transfer:**
   - Use SFTP/SCP, not FTP
   - Password-protect archives
   - Use secure file sharing platforms

---

## 🏁 Conclusion

This guide has covered:

✅ **Wireshark Basics** - Interface, packet dissection, navigation, filtering  
✅ **Packet Operations** - Statistics, protocols, advanced filtering  
✅ **Traffic Analysis** - Detecting scans, MITM, tunneling, credential theft  
✅ **Best Practices** - Optimization, automation, reporting  
✅ **Advanced Techniques** - Custom dissectors, tool integration  

### Next Steps

1. **Practice Regularly** - Use sample captures
2. **Join Community** - Participate in forums
3. **Stay Updated** - Follow security blogs
4. **Build Lab** - Set up test environment
5. **Obtain Certifications** - WCNA (Wireshark Certified Network Analyst)

### Key Takeaways

🎯 **Start with statistics** before diving into packets  
🎯 **Master display filters** - they're your most powerful tool  
🎯 **Document everything** - Good notes make great reports  
🎯 **Think like an attacker** - Understand what to look for  
🎯 **Automate repetitive tasks** - Use tshark and scripts  

---

📝 Quick Reference Card
┌─────────────────────────────────────────────────────┐
│  WIRESHARK QUICK REFERENCE                          │
├─────────────────────────────────────────────────────┤
│  SHORTCUTS                                          │
│  Ctrl+E    : Start/Stop capture                     │
│  Ctrl+K    : Capture options                        │
│  Ctrl+F    : Find packet                            │
│  Ctrl+G    : Go to packet                           │
│  Ctrl+M    : Mark packet                            │
│  Ctrl+→    : Next packet in conversation            │
│  Ctrl+←    : Previous packet in conversation        │
├─────────────────────────────────────────────────────┤
│  COMMON FILTERS                                     │
│  ip.addr == X          : Specific IP                │
│  tcp.port == X         : Specific port              │
│  http                  : HTTP traffic               │
│  dns                   : DNS traffic                │
│  tcp.flags.syn==1      : SYN packets                │
│  frame contains "X"    : Contains string            │
├─────────────────────────────────────────────────────┤
│  ANALYSIS WORKFLOW                                  │
│  1. Statistics → Capture Properties                 │
│  2. Statistics → Protocol Hierarchy                 │
│  3. Statistics → Conversations                      │
│  4. Apply relevant filters                          │
│  5. Follow streams for details                      │
│  6. Export objects if needed                        │
│  7. Document findings                               │
└─────────────────────────────────────────────────────┘
�

Happy Packet Hunting! 🦈
Remember: With great power comes great responsibility.
Use Wireshark ethically and legally.
�

📄 License
This guide is provided under the MIT License. Feel free to use, modify, and distribute with attribution.
🤝 Contributing
Contributions are welcome! Please:
Fork the repository
Create a feature branch
Submit a pull request
⭐ Acknowledgments
Wireshark Development Team
Security research community
All contributors to packet analysis tools
Last Updated: November 17, 2025
Version: 1.0
Maintained by: ATTA ULLAH KHAN 
