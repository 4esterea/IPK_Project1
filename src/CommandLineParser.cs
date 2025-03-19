using System;
using System.Collections.Generic;
using System.Linq;

namespace IPKScanner;

public partial class Program
{
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
}