using System.Diagnostics;

namespace TunRelayServer
{
    static class IptablesManager
    {
        static bool _cleared;

        static int Run(string args, bool logErrors = true)
        {
            var psi = new ProcessStartInfo("iptables", args)
            {
                RedirectStandardError = true,
                UseShellExecute = false
            };

            using var p = Process.Start(psi)!;
            p.WaitForExit();
            if (p.ExitCode != 0 && logErrors)
                Console.WriteLine($"iptables {args} failed: {p.StandardError.ReadToEnd()}");
            return p.ExitCode;
        }

        public static void Add(int[] tcpPorts, int[] udpPorts)
        {
            RemoveStaleCrossProtocolRules(tcpPorts, udpPorts);

            AddProtocol("tcp", tcpPorts);
            AddProtocol("udp", udpPorts);
        }

        public static void Remove(int[] tcpPorts, int[] udpPorts)
        {
            if (_cleared) return;
            _cleared = true;

            RemoveProtocol("tcp", tcpPorts);
            RemoveProtocol("udp", udpPorts);
        }

        static void AddProtocol(string protocol, int[] ports)
        {
            if (ports.Length == 0) return;

            RemoveProtocol(protocol, ports);

            var portList = string.Join(",", ports);
            Run($"-I INPUT -p {protocol} -m multiport --dports {portList} -j NFQUEUE --queue-num 100");
            Console.WriteLine($"iptables {protocol} rules added: {portList}");
        }

        static void RemoveProtocol(string protocol, int[] ports)
        {
            if (ports.Length == 0) return;

            var portList = string.Join(",", ports);
            int removed = 0;
            while (Run($"-D INPUT -p {protocol} -m multiport --dports {portList} -j NFQUEUE --queue-num 100", false) == 0)
            {
                removed++;
            }

            if (removed > 0)
                Console.WriteLine($"iptables {protocol} stale rules removed: {portList} x{removed}");
        }

        static void RemoveStaleCrossProtocolRules(int[] tcpPorts, int[] udpPorts)
        {
            var tcpOnlyCleanup = udpPorts.Except(tcpPorts).ToArray();
            var udpOnlyCleanup = tcpPorts.Except(udpPorts).ToArray();

            RemoveProtocol("tcp", tcpOnlyCleanup);
            RemoveProtocol("udp", udpOnlyCleanup);
        }
    }
}
