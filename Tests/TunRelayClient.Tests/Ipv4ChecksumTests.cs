using System.Buffers.Binary;
using Xunit;

public sealed class Ipv4ChecksumTests
{
    [Theory]
    [InlineData(20, 20, 4)]
    [InlineData(24, 24, 7)]
    public void RecalculatesTcpIncludingOptions(int ipHeaderLength, int tcpHeaderLength, int payloadLength)
    {
        byte[] packet = BuildTcp(ipHeaderLength, tcpHeaderLength, payloadLength);
        Ipv4Checksum.Recalculate(packet);
        AssertValid(packet, ipHeaderLength, 6);
    }

    [Theory]
    [InlineData(8)]
    [InlineData(7)]
    public void RecalculatesUdpIncludingOddPayload(int payloadLength)
    {
        byte[] packet = BuildUdp(payloadLength);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(26, 2), 0x1234);
        Ipv4Checksum.Recalculate(packet);
        AssertValid(packet, 20, 17);
    }

    [Fact]
    public void PreservesDisabledUdpChecksum()
    {
        byte[] packet = BuildUdp(7);
        Ipv4Checksum.Recalculate(packet);
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(26, 2)));
        Assert.Equal(0, Checksum(packet.AsSpan(0, 20)));
    }

    [Fact]
    public void WritesFfffWhenCalculatedUdpChecksumIsZero()
    {
        byte[] packet = BuildUdp(2);
        bool found = false;
        for (int value = 0; value <= ushort.MaxValue; value++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(28, 2), (ushort)value);
            packet.AsSpan(26, 2).Clear();
            if (TransportChecksum(packet, 20, 17) == 0) { found = true; break; }
        }

        Assert.True(found);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(26, 2), 0x1234);
        Ipv4Checksum.Recalculate(packet);
        Assert.Equal(ushort.MaxValue, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(26, 2)));
        AssertValid(packet, 20, 17);
    }

    [Theory]
    [InlineData(0x2000)]
    [InlineData(0x0001)]
    public void FragmentsOnlyRecalculateIpv4Header(int fragmentField)
    {
        byte[] packet = BuildTcp(20, 20, 8);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6, 2), (ushort)fragmentField);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(36, 2), 0x1234);
        Ipv4Checksum.Recalculate(packet);
        Assert.Equal(0, Checksum(packet.AsSpan(0, 20)));
        Assert.Equal(0x1234, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(36, 2)));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void InvalidOrTruncatedLengthDoesNotMutatePacket(bool oversized)
    {
        byte[] valid = BuildUdp(4);
        byte[] packet = oversized ? valid : valid[..^1];
        if (oversized) BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)(packet.Length + 1));
        byte[] original = packet.ToArray();
        Ipv4Checksum.Recalculate(packet);
        Assert.Equal(original, packet);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(17)]
    public void InvalidTransportOnlyRecalculatesIpv4Header(int protocol)
    {
        byte[] packet = protocol == 6 ? BuildTcp(20, 20, 4) : BuildUdp(4);
        int checksumOffset;
        if (protocol == 6)
        {
            packet[32] = 0;
            checksumOffset = 36;
        }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(24, 2), 8);
            checksumOffset = 26;
        }

        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(checksumOffset, 2), 0x1234);
        Ipv4Checksum.Recalculate(packet);

        Assert.Equal(0, Checksum(packet.AsSpan(0, 20)));
        Assert.Equal(0x1234, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(checksumOffset, 2)));
    }

    private static byte[] BuildTcp(int ihl, int thl, int payload)
    {
        byte[] packet = BuildIp(ihl, thl + payload, 6);
        int o = ihl;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(o, 2), 12345);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(o + 2, 2), 443);
        packet[o + 12] = (byte)((thl / 4) << 4);
        packet[o + 13] = 0x18;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(o + 14, 2), 65535);
        packet.AsSpan(20, ihl - 20).Fill(1);
        packet.AsSpan(o + 20, thl - 20).Fill(2);
        for (int i = o + thl; i < packet.Length; i++) packet[i] = (byte)i;
        return packet;
    }

    private static byte[] BuildUdp(int payload)
    {
        byte[] packet = BuildIp(20, 8 + payload, 17);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20, 2), 12345);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22, 2), 53);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(24, 2), (ushort)(8 + payload));
        for (int i = 28; i < packet.Length; i++) packet[i] = (byte)(i * 3);
        return packet;
    }

    private static byte[] BuildIp(int ihl, int transportLength, byte protocol)
    {
        byte[] packet = new byte[ihl + transportLength];
        packet[0] = (byte)(0x40 | ihl / 4);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
        packet[8] = 64; packet[9] = protocol;
        packet[12] = 192; packet[14] = 2; packet[15] = 10;
        packet[16] = 198; packet[17] = 51; packet[18] = 100; packet[19] = 20;
        return packet;
    }

    private static void AssertValid(byte[] packet, int ihl, byte protocol)
    {
        Assert.Equal(0, Checksum(packet.AsSpan(0, ihl)));
        Assert.Equal(0, TransportChecksum(packet, ihl, protocol));
    }

    private static ushort TransportChecksum(byte[] packet, int ihl, byte protocol)
    {
        ulong sum = Sum(packet.AsSpan(12, 8)) + protocol + (uint)(packet.Length - ihl);
        return Fold(sum + Sum(packet.AsSpan(ihl)));
    }

    private static ushort Checksum(ReadOnlySpan<byte> data) => Fold(Sum(data));
    private static ulong Sum(ReadOnlySpan<byte> data)
    {
        ulong sum = 0; int i = 0;
        for (; i + 1 < data.Length; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i, 2));
        if (i < data.Length) sum += (uint)data[i] << 8;
        return sum;
    }
    private static ushort Fold(ulong sum)
    {
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }
}
