# OMEGA: L4 Scanner

## Overview
L4 Scanner is a network port scanner that uses TCP and UDP scanning techniques to determine the state of specified ports on target hosts. The scanner supports both IPv4 and IPv6, and can work with different network interfaces.

## Executive Summary: Network Port Scanning Theory

### Fundamental Concepts
Port scanning relies on analyzing how network services respond to 
specific packet types. Each service on a host is identified by an IP address and port number combination.

### TCP Scanning
- Uses incomplete TCP handshake ("half-open" scanning)
- Scanner sends SYN packet, analyzes response:
  - SYN+ACK response = open port
  - RST response = closed port
  - No response = filtered port

### UDP Scanning
- Connectionless protocol creates challenges for scanning
- Scanner sends UDP packets and:
  - ICMP "port unreachable" response = closed port
  - No response = potentially open port

## Interesting source code sections

### TCP Scanning Implementation Details

The `TCPScanner` class uses a combination of raw socket programming and packet capture to implement SYN scanning:

- **Packet Capture**: Uses LibPcapLiveDevice to capture TCP response packets
- **SYN Packet Generation**: Creates TCP SYN packets through socket manipulation
- **Response Analysis**:
  ```csharp
  byte flags = packet[tcpOffset + 13];
  
  if ((flags & TCP_RST) != 0)
      return "closed";
  if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK))
      return "open";
  
### UDP Scanning Implementation Details

#### ICMP Response Monitoring
The scanner uses raw socket programming to detect closed ports by capturing ICMP "port unreachable" messages:

```csharp
  // Check for ICMP Port Unreachable
  if (bytesRead >= MIN_ICMP_PACKET_SIZE)
  {
      int ipHeaderLength = (buffer[0] & 0x0F) * 4;
      byte icmpType = buffer[ipHeaderLength];
      byte icmpCode = buffer[ipHeaderLength + 1];
  
      // ICMP Port Unreachable
      if (icmpType == ICMP_TYPE_DEST_UNREACHABLE &&
          icmpCode == ICMP_CODE_PORT_UNREACHABLE)
      {
          // Extract original packet info from ICMP payload
          int originalHeaderStart = ipHeaderLength + ICMP_HEADER_SIZE;
          // ...
          // Verify this is the ICMP response to our probe
          if (srcPort == localPort)
          {
              return "closed";
          }
      }
  }
```
## Usage
```
./ipk-l4-scan [-i interface | --interface interface] [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] {-w timeout} [hostname | ip-address]
```

Parameters:
- `-i of --interface`: Network interface to use
- `-t or --pt`: Comma-separated list of TCP ports to scan
- `-u or --pu`: Comma-separated list of UDP ports to scan
- `-w or --wait`: Timeout in milliseconds
- `<host>`: Target hostname or IP address

## Testing

### Test Case 1: Launching the Application Without Arguments

**What was tested:**
The application's behavior when launched without any command-line arguments.

**Why it was tested:**
To verify that the program correctly displays a list of active network interfaces when no parameters are provided, which is required functionality according to the specification.

**Command**: 

```
./ipk-l4-scan
```
**Output**:

```
Active network interfaces:
  lo (lo)
    IP: 127.0.0.1
    IP: 10.255.255.254
    IP: ::1
    MAC: 000000000000
  eth0 (eth0)
    IP: 172.30.56.121
    IP: fe80::215:5dff:fe17:d145%2
    MAC: 00155D17D145
```

**Expected output**:

```
Active network interfaces:
  lo (lo)
    IP: 127.0.0.1
    IP: 10.255.255.254
    IP: ::1
    MAC: 000000000000
  eth0 (eth0)
    IP: 172.30.56.121
    IP: fe80::215:5dff:fe17:d145%2
    MAC: 00155D17D145
```

### Test Case 2: Launch with -i Option Only

**What was tested:**
The application's behavior when launched with only the -i option without specifying a value.

**Why it was tested:**
To verify that the program correctly displays a list of active network interfaces when only the interface flag is provided without a value, which is required functionality according to the specification.

**Command**:

```
./ipk-l4-scan -i
```
**Output**:

```
Active network interfaces:
  lo (lo)
    IP: 127.0.0.1
    IP: 10.255.255.254
    IP: ::1
    MAC: 000000000000
  eth0 (eth0)
    IP: 172.30.56.121
    IP: fe80::215:5dff:fe17:d145%2
    MAC: 00155D17D145
```

**Expected output**:

```
Active network interfaces:
  lo (lo)
    IP: 127.0.0.1
    IP: 10.255.255.254
    IP: ::1
    MAC: 000000000000
  eth0 (eth0)
    IP: 172.30.56.121
    IP: fe80::215:5dff:fe17:d145%2
    MAC: 00155D17D145
```

### Test Case 3: Launching with Invalid Arguments

**What was tested:**
The application's behavior when launched with invalid command-line arguments.

**Why it was tested:**
To verify that the program correctly detects and reports invalid parameters, providing appropriate error messages to users.

**Command**:

```
./ipk-l4-scan --invalid-option
```
**Output**:

```
Error: Unknown option: --invalid-option
```

**Expected output**:

```
Error: Unknown option: --invalid-option
```

### Test Case 4: Scanning Localhost Using Loopback Interface

**What was tested:**
The application's ability to use the loopback interface to scan TCP and UDP ports on the local machine.

**Why it was tested:**
To verify that the scanner can properly utilize the loopback interface for local scanning, demonstrating correct interface selection and packet capture capabilities.

**Command**:

```
./ipk-l4-scan -i lo -t 22,80,443 -u 53,323 localhost
```
**Output**:

```
127.0.0.1 22 tcp closed
127.0.0.1 80 tcp closed
127.0.0.1 443 tcp closed
127.0.0.1 53 udp closed
127.0.0.1 323 udp open
```

**Expected output**:

```
127.0.0.1 22 tcp closed
127.0.0.1 80 tcp closed
127.0.0.1 443 tcp closed
127.0.0.1 53 udp closed
127.0.0.1 323 udp open
```

### Test Case 5: Scanning Localhost Using eth0 Interface

**What was tested:**
The application's ability to use a non-loopback interface (eth0) to scan TCP and UDP ports on the local machine.

**Why it was tested:**
To verify that the scanner can properly use a physical network interface to scan the local machine, demonstrating the ability to route scanning traffic through different interfaces.

**Command**:

```
./ipk-l4-scan -i eth0 -t 22,80,443 -u 53,323 localhost
```
**Output**:

```
127.0.0.1 22 tcp closed
127.0.0.1 80 tcp closed
127.0.0.1 443 tcp closed
127.0.0.1 53 udp closed
127.0.0.1 323 udp open
```

**Expected output**:

```
127.0.0.1 22 tcp closed
127.0.0.1 80 tcp closed
127.0.0.1 443 tcp closed
127.0.0.1 53 udp closed
127.0.0.1 323 udp open
```

### Test Case 6: Scanning External Host Using eth0 Interface

**What was tested:**
The application's ability to scan TCP and UDP ports on an external host (www.vut.cz) using a physical network interface (eth0).

**Why it was tested:**
To verify that the scanner correctly detects the state of ports on a remote server over the internet, demonstrating the scanner's capability to handle external host scanning.

**Command**:

```
./ipk-l4-scan -i eth0 -t 80,112,113 -u 80,112,113  www.vut.cz
```
**Output**:

```
147.229.2.90 80 tcp open
147.229.2.90 112 tcp filtered
147.229.2.90 113 tcp closed
147.229.2.90 80 udp open
147.229.2.90 112 udp open
147.229.2.90 113 udp open
```

**Expected output**:

```
147.229.2.90 80 tcp open
147.229.2.90 112 tcp filtered
147.229.2.90 113 tcp closed
147.229.2.90 80 udp open
147.229.2.90 112 udp open
147.229.2.90 113 udp open
```

### Test Case 7: Scanning External Host Using Loopback Interface

**What was tested:**
The application's ability to scan TCP and UDP ports on an external host (www.vut.cz) using the loopback interface (lo).

**Why it was tested:**
To verify the behavior when attempting to scan an external host through the loopback interface, which typically lacks routing capabilities to external networks.

**Command**:

```
./ipk-l4-scan -i lo -t 80,112,113 -u 80,112,113  www.vut.cz
```
**Output**:

```
147.229.2.90 80 tcp filtered
147.229.2.90 112 tcp filtered
147.229.2.90 113 tcp filtered
147.229.2.90 80 udp open
147.229.2.90 112 udp open
147.229.2.90 113 udp open
```

**Expected output**:

```
147.229.2.90 80 tcp filtered
147.229.2.90 112 tcp filtered
147.229.2.90 113 tcp filtered
147.229.2.90 80 udp open
147.229.2.90 112 udp open
147.229.2.90 113 udp open
```

## Test Validation

All test cases were validated against Nmap 7.80 to ensure the port scanner produces accurate results.

## Bibliography
- Stevens, W. R., Fenner, B., & Rudoff, A. M. (2003). *UNIX Network Programming: The Sockets Networking API*
- SharpPcap documentation: https://github.com/dotpcap/sharppcap
- RFC 793 - Transmission Control Protocol: https://tools.ietf.org/html/rfc793