using System.Collections.Generic;

namespace IPKScanner;

public partial class Program
{
    public class CommandLineArguments
    {
        public string Interface { get; set; } = string.Empty;
        public List<int> TcpPorts { get; set; } = new List<int>();
        public List<int> UdpPorts { get; set; } = new List<int>();
        public int Timeout { get; set; } = 5000;
        public string Host { get; set; } = string.Empty;
        public bool ShowHelp { get; set; }
        public bool ShouldListInterfaces { get; set; }
    }
}