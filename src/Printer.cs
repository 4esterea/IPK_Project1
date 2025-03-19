using System;
using System.Net.NetworkInformation;

namespace IPKScanner;

public partial class Program
{
    public static class Printer
    {
        public static void ListActiveInterfaces()
        {
            Console.WriteLine("Active network interfaces:");
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up)
                {
                    Console.WriteLine($"  {ni.Name} ({ni.Description})");
                    foreach (var ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        Console.WriteLine($"    IP: {ip.Address}");
                    }

                    Console.WriteLine($"    MAC: {ni.GetPhysicalAddress()}");
                }
            }
        }
            
        public static void PrintHelp()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  ./ipk-l4-scan -i INTERFACE (-t PORTS | -u PORTS) [-w TIMEOUT] HOST");
            Console.WriteLine("  ./ipk-l4-scan -i\t\t\t\tList available interfaces");
            Console.WriteLine("  ./ipk-l4-scan -h\t\t\t\tShow this help");
            Console.WriteLine("\nRequired arguments:");
            Console.WriteLine("  -i, --interface <name>\tNetwork interface name");
            Console.WriteLine("  -t, --pt <ports>\t\tTCP ports (e.g. 80 or 1-100)");
            Console.WriteLine("  -u, --pu <ports>\t\tUDP ports (e.g. 53 or 1-65535)");
            Console.WriteLine("  HOST\t\t\t\tTarget hostname or IP address");
            Console.WriteLine("\nOptions:");
            Console.WriteLine("  -w, --wait <ms>\t\tTimeout in milliseconds (default: 5000)");
        }
    }
}