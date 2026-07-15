using TunRelayServer;
using Xunit;

namespace TunRelayServer.Tests;

public sealed class NfQueuePacketCaptureTests
{
    [Fact]
    public void CompleteIpv4PacketIsCaptured()
    {
        byte[] payload = CreateIpv4Packet(20, 20);
        Assert.True(NfQueuePacketCapture.TryCapture(payload, 20, out var packet));
        Assert.NotNull(packet);
        Assert.Equal(20, packet.Length);
        packet.Dispose();
    }

    [Fact]
    public void TruncatedPacketIsRejectedAndCounted()
    {
        TunnelStats.Reset();
        byte[] payload = CreateIpv4Packet(65_535, 65_531);
        Assert.False(NfQueuePacketCapture.TryCapture(payload, 65_535, out var packet));
        Assert.Null(packet);
        Assert.Contains("truncatedPackets  : 1", TunnelStats.Snapshot());
    }

    [Fact]
    public void Ipv4TotalLengthBeyondPayloadIsRejected()
    {
        byte[] payload = CreateIpv4Packet(24, 20);
        Assert.False(NfQueuePacketCapture.TryCapture(payload, 20, out var packet));
        Assert.Null(packet);
    }

    [Fact]
    public void OriginalLengthIsReadFromNetlinkMetadata()
    {
        byte[] message = CreateNetlinkMessage(42, 65_535);
        Assert.True(NfQueueNetlinkMetadata.TryGetOriginalLength(message, 42, out uint length));
        Assert.Equal(65_535u, length);
    }

    private static byte[] CreateIpv4Packet(ushort totalLength, int capturedLength)
    {
        var packet = new byte[capturedLength];
        if (capturedLength > 0)
            packet[0] = 0x45;
        if (capturedLength > 3)
        {
            packet[2] = (byte)(totalLength >> 8);
            packet[3] = (byte)totalLength;
        }
        return packet;
    }

    private static byte[] CreateNetlinkMessage(uint packetId, uint originalLength)
    {
        var message = new byte[40];
        BitConverter.GetBytes(message.Length).CopyTo(message, 0);
        BitConverter.GetBytes((ushort)11).CopyTo(message, 20);
        BitConverter.GetBytes((ushort)1).CopyTo(message, 22);
        WriteBigEndian(message, 24, packetId);
        BitConverter.GetBytes((ushort)8).CopyTo(message, 32);
        BitConverter.GetBytes((ushort)13).CopyTo(message, 34);
        WriteBigEndian(message, 36, originalLength);
        return message;
    }

    private static void WriteBigEndian(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value >> 24);
        buffer[offset + 1] = (byte)(value >> 16);
        buffer[offset + 2] = (byte)(value >> 8);
        buffer[offset + 3] = (byte)value;
    }
}
