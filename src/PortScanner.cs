using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace OMEGAL4Scanner;

public static class PortScanner
{
    public static async Task Scan(CommandLineArguments args)
    {
        var ipAddresses = Dns.GetHostAddresses(args.Host);

        foreach (var ip in ipAddresses)
        {
                
            if (args.TcpPorts.Any())
            {
                var tcpScanner = new TCPScanner(args.Interface, args.Timeout);
                var tcpResults = await tcpScanner.Scan(ip, args.TcpPorts);

                var sortedTcpResults = tcpResults.OrderBy(kvp => kvp.Key);
                foreach (var (port, status) in sortedTcpResults)
                {
                    Console.WriteLine($"{ip} {port} tcp {status.ToLower()}");
                }
            }
                
            if (args.UdpPorts.Any())
            {
                var udpScanner = new UDPScanner(args.Interface, args.Timeout);
                var udpResults = await udpScanner.Scan(ip, args.UdpPorts);
                    
                foreach (var (port, status) in udpResults)
                {
                    Console.WriteLine($"{ip} {port} udp {status.ToLower()}");
                }
            }
                
        }
    }
}
