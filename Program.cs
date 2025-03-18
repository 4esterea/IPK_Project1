using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;

namespace IPKScanner
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            try
            {
                var parser = new CommandLineParser(args);
                var arguments = parser.Parse();

                if (arguments.ShowHelp)
                {
                    HelpPrinter.PrintHelp();
                    return;
                }

                if (arguments.ShouldListInterfaces)
                {
                    InterfaceLister.ListActiveInterfaces();
                    return;
                }

                ArgumentValidator.Validate(arguments);
                await PortScanner.Scan(arguments);
            }
            catch (ArgumentException ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Environment.Exit(1);
            }
        }

        public class CommandLineArguments
        {
            public string Interface { get; set; }
            public List<int> TcpPorts { get; set; } = new List<int>();
            public List<int> UdpPorts { get; set; } = new List<int>();
            public int Timeout { get; set; } = 5000;
            public string Host { get; set; }
            public bool ShowHelp { get; set; }
            public bool ShouldListInterfaces { get; set; }
        }

        public class CommandLineParser
        {
            private readonly string[] _args;
            private readonly CommandLineArguments _arguments = new CommandLineArguments();
            private int _currentIndex;

            public CommandLineParser(string[] args) => _args = args;

            public CommandLineArguments Parse()
            {
                for (_currentIndex = 0; _currentIndex < _args.Length; _currentIndex++)
                {
                    var arg = _args[_currentIndex];
                    if (IsOption(arg) && !IsKnownOption(arg))
                    {
                        throw new ArgumentException($"Unknown option: {arg}");
                    }

                    switch (arg)
                    {
                        case "-h":
                        case "--help":
                            _arguments.ShowHelp = true;
                            return _arguments;
                        case "-i":
                        case "--interface":
                            ParseInterface();
                            break;
                        case "-t":
                        case "--pt":
                            ParsePorts(_arguments.TcpPorts);
                            break;
                        case "-u":
                        case "--pu":
                            ParsePorts(_arguments.UdpPorts);
                            break;
                        case "-w":
                        case "--wait":
                            ParseTimeout();
                            break;
                        default:
                            ParseHost(arg);
                            break;
                    }
                }

                CheckForInterfaceListing();
                return _arguments;
            }

            private void ParseInterface()
            {
                if (_currentIndex + 1 >= _args.Length || IsOption(_args[_currentIndex + 1]))
                {
                    _arguments.ShouldListInterfaces = true;
                    return;
                }

                _arguments.Interface = _args[++_currentIndex];
            }

            private void ParsePorts(List<int> ports)
            {
                if (_currentIndex + 1 >= _args.Length)
                    throw new ArgumentException("Ports specification is missing");

                var portSpec = _args[++_currentIndex];
                ports.AddRange(PortParser.Parse(portSpec));
            }

            private void ParseTimeout()
            {
                if (_currentIndex + 1 >= _args.Length)
                    throw new ArgumentException("Timeout value is missing");

                if (!int.TryParse(_args[++_currentIndex], out int timeout))
                    throw new ArgumentException("Invalid timeout value");

                _arguments.Timeout = timeout;
            }

            private void ParseHost(string host)
            {
                if (IsOption(host))
                    throw new ArgumentException($"Invalid host specification: {host}");

                if (!string.IsNullOrEmpty(_arguments.Host))
                    throw new ArgumentException("Multiple hosts specified");

                _arguments.Host = host;
            }

            private bool IsOption(string arg) => arg.StartsWith("-");

            private bool IsKnownOption(string arg) => new[]
            {
                "-h", "--help",
                "-i", "--interface",
                "-t", "--pt",
                "-u", "--pu",
                "-w", "--wait"
            }.Contains(arg);

            private void CheckForInterfaceListing()
            {
                bool interfaceWithoutValue =
                    _arguments.ShouldListInterfaces ||
                    (string.IsNullOrEmpty(_arguments.Interface) &&
                     _args.Any(a => a is "-i" or "--interface"));

                bool hasOtherParameters =
                    _args.Except(new[] { "-i", "--interface" }).Any();

                if (interfaceWithoutValue && !hasOtherParameters)
                {
                    _arguments.ShouldListInterfaces = true;
                }
                else if (interfaceWithoutValue && hasOtherParameters)
                {
                    throw new ArgumentException(
                        "Option -i/--interface requires a value when used with other parameters");
                }
            }
        }

        public static class PortParser
        {
            public static IEnumerable<int> Parse(string portSpec)
            {
                var ports = new List<int>();
                foreach (var part in portSpec.Split(','))
                {
                    if (part.Contains("-"))
                    {
                        var range = part.Split('-');
                        if (range.Length != 2 || !int.TryParse(range[0], out int start) ||
                            !int.TryParse(range[1], out int end))
                            throw new ArgumentException($"Invalid port range: {part}");

                        ports.AddRange(GeneratePortRange(start, end));
                    }
                    else
                    {
                        if (!int.TryParse(part, out int port))
                            throw new ArgumentException($"Invalid port number: {part}");

                        ports.Add(port);
                    }
                }

                return ports;
            }

            private static IEnumerable<int> GeneratePortRange(int start, int end)
            {
                for (int port = start; port <= end; port++)
                {
                    yield return port;
                }
            }
        }

        public static class ArgumentValidator
        {
            public static void Validate(CommandLineArguments args)
            {
                if (args.ShowHelp || args.ShouldListInterfaces)
                    return;

                var errors = new List<string>();

                if (string.IsNullOrEmpty(args.Host))
                    errors.Add("Host is required");

                if (args.TcpPorts.Count == 0 && args.UdpPorts.Count == 0)
                    errors.Add("At least one port range (TCP or UDP) must be specified");

                if (string.IsNullOrEmpty(args.Interface))
                    errors.Add("Network interface is required");

                if (errors.Count > 0)
                    throw new ArgumentException(string.Join("\n", errors));
            }
        }

        public static class HelpPrinter
        {
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

        public static class InterfaceLister
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
        }

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

                        foreach (var (port, status) in tcpResults)
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
                            Console.WriteLine($"{ip} {port} udp {status.ToString().ToLower()}");
                        }
                    }
                    
                }
            }
        }
    }
}