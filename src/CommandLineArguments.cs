using System.Collections.Generic;

namespace OMEGAL4Scanner;

public class CommandLineArguments
{
    public string Interface { get; set; } = string.Empty;
    public List<int> TcpPorts { get; set; } = [];
    public List<int> UdpPorts { get; set; } = [];
    public int Timeout { get; set; } = 5000;
    public string Host { get; set; } = string.Empty;
    public bool ShowHelp { get; set; }
    public bool ShouldListInterfaces { get; set; }
}
