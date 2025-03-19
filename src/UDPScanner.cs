using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace IPKScanner
{
    public class UDPScanner
    {
        private readonly string _interface;
        private readonly int _timeout;

        // Network protocol constants
        private const int BUFFER_SIZE = 4096;
        private const int MIN_ICMP_PACKET_SIZE = 28;
        private const int ICMP_TYPE_DEST_UNREACHABLE = 3;
        private const int ICMP_CODE_PORT_UNREACHABLE = 3;
        private const int ICMP_HEADER_SIZE = 8;
        private const int IP_HEADER_MIN_SIZE = 20;
        private const int PORT_FIELD_SIZE = 2;
        private const int BYTE_SHIFT = 8;
        private const int LOOP_DELAY_MS = 5;
        private const byte EMPTY_BYTE = 0x00;

        public UDPScanner(string networkInterface, int timeout)
        {
            _interface = networkInterface;
            _timeout = timeout;
        }

        public async Task<Dictionary<int, string>> Scan(IPAddress ipAddress, List<int> ports)
        {
            var tasks = ports.Select(port => ScanPort(ipAddress, port));
            var results = await Task.WhenAll(tasks);

            return ports.Zip(results, (port, status) => new { port, status })
                .ToDictionary(x => x.port, x => x.status);
        }

        private async Task<string> ScanPort(IPAddress ipAddress, int port)
        {
            using var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            using var icmpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
            try
            {
                // Configure sockets
                icmpSocket.ReceiveTimeout = _timeout;
                icmpSocket.Bind(new IPEndPoint(IPAddress.Any, 0));

                // Create and bind a specific local endpoint for this scan
                IPEndPoint localEndPoint;
                
                // Bind socket to the specified network interface
                IPAddress interfaceIp = GetInterfaceIPAddress(_interface);
                localEndPoint = new IPEndPoint(interfaceIp, 0);

                udpSocket.Bind(localEndPoint);
                int localPort = ((IPEndPoint)udpSocket.LocalEndPoint!).Port;

                // Send UDP packet
                var remoteEndPoint = new IPEndPoint(ipAddress, port);
                byte[] data = [EMPTY_BYTE];
                udpSocket.SendTo(data, remoteEndPoint);

                // Start a cancellation token for our timeout
                using var cts = new CancellationTokenSource(_timeout);

                // Listen for ICMP response
                byte[] buffer = new byte[BUFFER_SIZE];

                while (!cts.IsCancellationRequested)
                {
                    if (icmpSocket.Available > 0)
                    {
                        int bytesRead = icmpSocket.Receive(buffer);

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
                                if (bytesRead >= originalHeaderStart + IP_HEADER_MIN_SIZE)
                                {
                                    // Extract source port from original UDP header in ICMP payload
                                    int srcPortOffset = originalHeaderStart + IP_HEADER_MIN_SIZE;
                                    if (bytesRead >= srcPortOffset + PORT_FIELD_SIZE)
                                    {
                                        int srcPort = (buffer[srcPortOffset] << BYTE_SHIFT) | 
                                                      buffer[srcPortOffset + 1];

                                        // If this matches our local port, it's our ICMP response
                                        if (srcPort == localPort)
                                        {
                                            return "closed";
                                        }
                                    }
                                }
                            }
                        }
                    }
                    await Task.Delay(LOOP_DELAY_MS, cts.Token); // Small delay to prevent CPU spinning
                }

                return "open"; // No matching ICMP response = likely open
            }
            catch (OperationCanceledException)
            {
                return "open"; // Timeout = likely open
            }
            catch (Exception)
            {
                return "closed"; // Other error = likely closed
            }
        }

        private IPAddress GetInterfaceIPAddress(string interfaceName)
        {
            // Method implementation unchanged
            var networkInterface = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(ni => ni.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase));

            if (networkInterface == null)
                throw new ArgumentException($"Network interface '{interfaceName}' not found");

            var ipProperties = networkInterface.GetIPProperties();
            var ipv4Address = ipProperties.UnicastAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;

            if (ipv4Address == null)
                throw new ArgumentException($"No IPv4 address found on interface '{interfaceName}'");

            return ipv4Address;
        }
    }
}