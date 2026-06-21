namespace TunRelayServer
{
    // 基于 5 元组(srcIP/dstIP/proto/sport/dport)把 IP 包稳定映射到某条并行连接。
    internal static class FlowHash
    {
        public static int Index(ReadOnlySpan<byte> packet, int connectionCount)
        {
            if (connectionCount <= 1) return 0;
            if (packet.Length < 20 || (packet[0] >> 4) != 4) return 0;

            uint h = 2166136261u; // FNV-1a 32-bit
            for (int i = 12; i < 20; i++) // src + dst IP
                h = (h ^ packet[i]) * 16777619u;

            byte proto = packet[9];
            h = (h ^ proto) * 16777619u;

            if (proto == 6 || proto == 17) // TCP / UDP
            {
                int ihl = (packet[0] & 0x0F) * 4;
                if (ihl >= 20 && packet.Length >= ihl + 4)
                    for (int i = ihl; i < ihl + 4; i++) // sport + dport
                        h = (h ^ packet[i]) * 16777619u;
            }

            return (int)(h % (uint)connectionCount);
        }
    }
}
