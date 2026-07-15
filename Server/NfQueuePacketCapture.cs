using System.Buffers.Binary;

namespace TunRelayServer;

internal static class NfQueuePacketCapture
{
    public static unsafe bool TryCapture(
        IntPtr payload,
        int capturedLength,
        uint originalLength,
        out PacketBuffer? packet)
    {
        var span = new ReadOnlySpan<byte>((void*)payload, capturedLength);
        return TryCapture(span, originalLength, out packet);
    }

    public static bool TryCapture(
        ReadOnlySpan<byte> payload,
        uint originalLength,
        out PacketBuffer? packet)
    {
        int headerLength = payload.Length > 0 ? (payload[0] & 0x0f) * 4 : 0;
        bool completeIpv4Packet = originalLength == payload.Length
            && payload.Length >= 20
            && payload[0] >> 4 == 4
            && headerLength >= 20
            && headerLength <= payload.Length
            && BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2)) == payload.Length;

        if (!completeIpv4Packet)
        {
            TunnelStats.IncrementTruncatedPackets();
            packet = null;
            return false;
        }

        packet = PacketBuffer.Rent(payload.Length);
        payload.CopyTo(packet.Memory.Span);
        return true;
    }
}
