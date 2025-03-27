using System;
using System.Collections.Generic;

namespace OMEGAL4Scanner;

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
