using System;
using System.Collections.Generic;

namespace IPKScanner;

public partial class Program
{
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
}