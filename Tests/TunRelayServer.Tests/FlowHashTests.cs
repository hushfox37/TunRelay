using TunRelayServer;
using Xunit;

namespace TunRelayServer.Tests;

public sealed class FlowHashTests
{
    private static readonly int[] IperfSourcePorts =
    {
        49148, 49152, 49162, 49168, 49178, 49188, 49202, 49210,
        48774, 48782, 48792, 48802, 48814, 48826, 48840, 48842,
        54782, 54792, 54800, 54816, 54828, 54834, 54838, 54854
    };

    [Fact]
    public void StructuredIperfPortsUseEveryChannel()
    {
        int[] counts = new int[4];
        foreach (int port in IperfSourcePorts)
            counts[FlowHash.Index(CreateTcpPacket(port), counts.Length)]++;

        Assert.All(counts, count => Assert.InRange(count, 3, 9));
    }

    [Fact]
    public void SameFlowAlwaysUsesSameChannel()
    {
        byte[] packet = CreateTcpPacket(49148);
        int expected = FlowHash.Index(packet, 4);

        for (int i = 0; i < 100; i++)
            Assert.Equal(expected, FlowHash.Index(packet, 4));
    }

    private static byte[] CreateTcpPacket(int sourcePort)
    {
        var packet = new byte[40];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12] = 10;
        packet[13] = 204;
        packet[15] = 2;
        packet[16] = 203;
        packet[18] = 113;
        packet[19] = 1;
        packet[20] = (byte)(sourcePort >> 8);
        packet[21] = (byte)sourcePort;
        packet[22] = 0x14;
        packet[23] = 0x51;
        return packet;
    }
}
