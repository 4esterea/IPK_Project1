using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Collections.Concurrent;

namespace IPKScanner
{
    public class TCPScanner
    {
        private readonly string _interface;
        private readonly int _timeout;
        private readonly Random _random = new Random();
        private const int RETRY_DELAY = 500;

        // TCP flags
        private const byte TCP_SYN = 0x02;
        private const byte TCP_ACK = 0x10;
        private const byte TCP_RST = 0x04;

        public TCPScanner(string networkInterface, int timeout)
        {
            _interface = networkInterface;
            _timeout = timeout;
        }

        public async Task<Dictionary<int, string>> Scan(IPAddress ipAddress, List<int> ports)
        {
            var results = new Dictionary<int, string>();
            bool isIPv6 = ipAddress.AddressFamily == AddressFamily.InterNetworkV6;

            // Check if IPv6 is viable for external addresses
            if (isIPv6)
            {
                try {
                    var sourceIP = GetInterfaceIPAddress(_interface, true);
                    if (sourceIP.IsIPv6LinkLocal && !ipAddress.IsIPv6LinkLocal)
                    {
                        foreach (var port in ports)
                        {
                            results[port] = "filtered"; // Mark all as filtered without scanning
                        }
                        return results;
                    }
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine($"IPv6 scanning error: {ex.Message}");
                    foreach (var port in ports)
                    {
                        results[port] = "filtered"; // Mark all as filtered on error
                    }
                    return results;
                }
            }

            // Proceed with parallel scanning if IPv6 is viable or it's IPv4
            try
            {
                // Get device
                var device = GetCaptureDevice();
                device.Open(DeviceModes.Promiscuous);

                // Create filter for TCP packets from target IP
                device.Filter = $"tcp and src host {ipAddress}";

                // Create a list of tasks for each port
                var tasks = ports.Select(port => ScanPort(device, ipAddress, port));
                
                // Wait for all scan tasks to complete in parallel
                var scanResults = await Task.WhenAll(tasks);
                
                // Combine results into dictionary
                for (int i = 0; i < ports.Count; i++)
                {
                    results[ports[i]] = scanResults[i];
                }

                device.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Scanning error: {ex.Message}");
                foreach (var port in ports)
                {
                    if (!results.ContainsKey(port))
                        results[port] = "filtered";
                }
            }

            return results;
        }

        private async Task<string> ScanPort(ICaptureDevice device, IPAddress ipAddress, int port)
        {
            bool isIPv6 = ipAddress.AddressFamily == AddressFamily.InterNetworkV6;
            
            // Create a separate capture queue for this specific scan
            PacketArrivalEventHandler? handler = null;
            var captureQueue = new BlockingCollection<RawCapture>();
            var sourceIP = GetInterfaceIPAddress(_interface, isIPv6);
            int sourcePort = _random.Next(49152, 65535);
            bool captureStarted = false;

            try
            {
                // Register handler for this specific scan instance
                handler = (s, e) => {
                    var rawCapture = e.GetPacket();
    
                    if (IsRelevantPacket(rawCapture.Data, ipAddress, port, sourcePort))
                    {
                        captureQueue.Add(rawCapture);
                    }
                };

                device.OnPacketArrival += handler;
                device.StartCapture();
                captureStarted = true;

                // Send SYN packet
                SendSynPacket(sourceIP, ipAddress, sourcePort, port);

                // Wait with timeout
                var cts = new CancellationTokenSource(_timeout);

                try
                {
                    while (!cts.IsCancellationRequested)
                    {
                        if (captureQueue.TryTake(out var capture, 100))
                        {
                            // Process the captured packet
                            var result = ProcessPacket(capture.Data);
                            if (result != null)
                                return result;
                        }
                        await Task.Delay(10);
                    }

                    // Try one more time with retry
                    SendSynPacket(sourceIP, ipAddress, sourcePort, port);

                    cts = new CancellationTokenSource(RETRY_DELAY);
                    while (!cts.IsCancellationRequested)
                    {
                        if (captureQueue.TryTake(out var capture, 100))
                        {
                            var result = ProcessPacket(capture.Data);
                            if (result != null)
                                return result;
                        }
                        await Task.Delay(10);
                    }
                }
                catch (OperationCanceledException)
                {
                    // Timed out
                }

                return "filtered";
            }
            finally
            {
                if (captureStarted)
                {
                    device.OnPacketArrival -= handler; 
                }
            }
        }

        private string? ProcessPacket(byte[] packet)
        {
            try
            {
                int etherType = (packet[12] << 8) | packet[13];
                int ipOffset = 14;
                int tcpOffset;
        
                if (etherType == 0x0800) // IPv4
                {
                    int ipHeaderLength = (packet[ipOffset] & 0x0F) * 4;
                    tcpOffset = ipOffset + ipHeaderLength;
                }
                else if (etherType == 0x86DD) // IPv6
                {
                    // IPv6 header is fixed 40 bytes
                    tcpOffset = ipOffset + 40;
                }
                else
                {
                    return null; // Unknown packet type
                }
        
                byte flags = packet[tcpOffset + 13];
        
                if ((flags & TCP_RST) != 0)
                    return "closed";
                if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK))
                    return "open";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing packet: {ex.Message}");
            }
            return null;
        }

        private bool IsRelevantPacket(byte[] packet, IPAddress targetIP, int targetPort, int sourcePort)
        {
            bool isIPv6 = targetIP.AddressFamily == AddressFamily.InterNetworkV6;

            try
            {
                int etherType = (packet[12] << 8) | packet[13];
                int ipOffset = 14; // Ethernet header length
                
                if (isIPv6) // IPv6
                {
                    if (etherType != 0x86DD) return false; // Not an IPv6 packet
                    
                    // Check if version is 6 (first 4 bits should be 6)
                    if ((packet[ipOffset] >> 4) != 6) return false;
                    
                    // Check if protocol is TCP (next header = 6)
                    if (packet[ipOffset + 6] != 6) return false;
                    
                    // Check source IPv6 address (16 bytes)
                    byte[] srcIP = new byte[16];
                    Array.Copy(packet, ipOffset + 8, srcIP, 0, 16);
                    if (!new IPAddress(srcIP).Equals(targetIP)) return false;
                    
                    // TCP header starts after IPv6 header (40 bytes)
                    int tcpOffset = ipOffset + 40;
                    
                    // Extract ports
                    int srcPort = (packet[tcpOffset] << 8) | packet[tcpOffset + 1];
                    int dstPort = (packet[tcpOffset + 2] << 8) | packet[tcpOffset + 3];
                    
                    return srcPort == targetPort && dstPort == sourcePort;
                }
                else // IPv4
                {
                    // Original IPv4 implementation
                    if (etherType != 0x0800) return false;
                    if ((packet[14] >> 4) != 4) return false;
                    
                    int ipHeaderLength = (packet[14] & 0x0F) * 4;
                    
                    // Check source IP
                    byte[] srcIP = new byte[4];
                    Array.Copy(packet, ipOffset + 12, srcIP, 0, 4);
                    if (!new IPAddress(srcIP).Equals(targetIP)) return false;
                    
                    // Check if TCP (protocol 6)
                    if (packet[ipOffset + 9] != 6) return false;
                    
                    int tcpOffset = ipOffset + ipHeaderLength;
                    
                    // Extract ports
                    int srcPort = (packet[tcpOffset] << 8) | packet[tcpOffset + 1];
                    int dstPort = (packet[tcpOffset + 2] << 8) | packet[tcpOffset + 3];
                    
                    return srcPort == targetPort && dstPort == sourcePort;
                }
            }
            catch
            {
                return false;
            }
        }

        

        private void SendSynPacket(IPAddress srcIP, IPAddress dstIP, int srcPort, int dstPort)
        {
            // Create a new socket
            Socket socket = new Socket(dstIP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
    
            try
            {
                // Configure socket options
                socket.Blocking = false;
                socket.ExclusiveAddressUse = false;
        
                // Bind to source IP and port if specified
                if (srcPort > 0)
                {
                    socket.Bind(new IPEndPoint(srcIP, srcPort));
                }
        
                // Begin the connection attempt (SYN packet)
                var result = socket.BeginConnect(
                    new IPEndPoint(dstIP, dstPort),
                    null, null);
            
                // Don't wait for connection completion - we just want to send the SYN
                // The response will be captured by our packet capture handler
            }
            catch (SocketException)
            {
                // Ignore errors - packet capture will handle the response
            }
            finally
            {
                // Close socket without completing connection
                socket.Close();
            }
        }
        
        private LibPcapLiveDevice GetCaptureDevice()
        {
            var devices = LibPcapLiveDeviceList.Instance;
            foreach (var dev in devices)
            {
                if (dev.Name == _interface || dev.Description.Contains(_interface))
                    return dev;
            }
            throw new ArgumentException($"Interface `{_interface}` not found");
        }

        private IPAddress GetInterfaceIPAddress(string interfaceName, bool useIPv6 = false)
        {
            var networkInterface = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(ni => ni.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase));
            if (networkInterface == null)
                throw new ArgumentException($"Interface `{interfaceName}` not found");

            var addressFamily = useIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            
            if (useIPv6)
            {
                // Find IPv6 addresses and categorize them
                var allIpv6Addresses = networkInterface.GetIPProperties().UnicastAddresses
                    .Where(a => a.Address.AddressFamily == addressFamily)
                    .ToList();
                
                
                // Look for a global IPv6 address (not link-local)
                var globalAddress = allIpv6Addresses.FirstOrDefault(a => !a.Address.IsIPv6LinkLocal);
                if (globalAddress != null)
                {
                    return globalAddress.Address;
                }
                
                
                if (allIpv6Addresses.Any())
                {
                    return allIpv6Addresses.First().Address;
                }
                
                throw new ArgumentException("No IPv6 addresses found on the selected interface");
            }
            else
            {
                // Original IPv4 logic
                var ipAddress = networkInterface.GetIPProperties().UnicastAddresses
                    .FirstOrDefault(a => a.Address.AddressFamily == addressFamily)?.Address;
                    
                if (ipAddress == null)
                    throw new ArgumentException($"No IPv4 address found on interface `{interfaceName}`");
                    
                return ipAddress;
            }
        }
    }
}