using System;
using System.Threading.Tasks;

namespace IPKScanner
{
    public partial class Program
    {
        public static async Task Main(string[] args)
        {
            try
            {
                var parser = new CommandLineParser(args);
                var arguments = parser.Parse();

                if (arguments.ShowHelp)
                {
                    Printer.PrintHelp();
                    return;
                }

                if (arguments.ShouldListInterfaces)
                {
                    Printer.ListActiveInterfaces();
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
    }
}