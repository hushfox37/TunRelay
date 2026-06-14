using System.Diagnostics;

namespace VirtualIPServer
{
    static class IptablesManager
    {
        static bool _cleared;

        static void Run(string args)
        {
            var psi = new ProcessStartInfo("iptables", args)
            {
                RedirectStandardError = true,
                UseShellExecute = false
            };

            using var p = Process.Start(psi)!;
            p.WaitForExit();
            if (p.ExitCode != 0)
                Console.WriteLine($"iptables {args} 失败: {p.StandardError.ReadToEnd()}");
        }

        public static void Add(int[] ports)
        {
            var portList = string.Join(",", ports);
            Run($"-I INPUT -p tcp -m multiport --dports {portList} -j NFQUEUE --queue-num 100");
            Run($"-I INPUT -p udp -m multiport --dports {portList} -j NFQUEUE --queue-num 100");
            Console.WriteLine($"iptables 规则已添加: {portList}");
        }

        public static void Remove(int[] ports)
        {
            if (_cleared) return;
            _cleared = true;

            var portList = string.Join(",", ports);
            Run($"-D INPUT -p tcp -m multiport --dports {portList} -j NFQUEUE --queue-num 100");
            Run($"-D INPUT -p udp -m multiport --dports {portList} -j NFQUEUE --queue-num 100");
            Console.WriteLine($"iptables 规则已清理: {portList}");
        }
    }
}
