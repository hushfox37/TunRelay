using System.Buffers.Binary;

public static class Ipv4Checksum
{
    private const byte TcpProtocol = 6;
    private const byte UdpProtocol = 17;

    public static void Recalculate(Span<byte> packet)
    {
        if (packet.Length < 20 || packet[0] >> 4 != 4)
            return;

        int headerLength = (packet[0] & 0x0F) * 4;
        if (headerLength < 20 || headerLength > packet.Length)
            return;

        int totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
        if (totalLength < headerLength || totalLength > packet.Length)
            return;

        Span<byte> datagram = packet.Slice(0, totalLength);
        datagram.Slice(10, 2).Clear();
        BinaryPrimitives.WriteUInt16BigEndian(datagram.Slice(10, 2), Complete(Sum(datagram.Slice(0, headerLength))));

        // Any fragment, including the first fragment with MF set, has no complete
        // transport segment. Only its IPv4 header checksum may be recomputed.
        ushort fragment = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(6, 2));
        if ((fragment & 0x3FFF) != 0)
            return;

        byte protocol = datagram[9];
        int transportLength = totalLength - headerLength;
        int checksumOffset;
        if (protocol == TcpProtocol)
        {
            if (transportLength < 20)
                return;

            int tcpHeaderLength = (datagram[headerLength + 12] >> 4) * 4;
            if (tcpHeaderLength < 20 || tcpHeaderLength > transportLength)
                return;
            checksumOffset = headerLength + 16;
        }
        else if (protocol == UdpProtocol)
        {
            if (transportLength < 8)
                return;

            int udpLength = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(headerLength + 4, 2));
            if (udpLength != transportLength)
                return;
            checksumOffset = headerLength + 6;

            // A zero checksum explicitly disables UDP checksumming for IPv4.
            // Preserve that protocol-level choice instead of enabling it here.
            if (BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(checksumOffset, 2)) == 0)
                return;
        }
        else
        {
            return;
        }

        datagram.Slice(checksumOffset, 2).Clear();

        ulong sum = Sum(datagram.Slice(12, 8));
        sum += protocol;
        sum += (uint)transportLength;
        sum += Sum(datagram.Slice(headerLength, transportLength));

        ushort checksum = Complete(sum);
        if (protocol == UdpProtocol && checksum == 0)
            checksum = 0xFFFF;

        BinaryPrimitives.WriteUInt16BigEndian(datagram.Slice(checksumOffset, 2), checksum);
    }

    internal static ulong Sum(ReadOnlySpan<byte> data)
    {
        ulong sum = 0;
        int offset = 0;

        // Four network-order 16-bit words per load. Splitting the 64-bit value
        // avoids alignment assumptions and preserves one's-complement word order.
        while (offset + sizeof(ulong) <= data.Length)
        {
            ulong value = BinaryPrimitives.ReadUInt64BigEndian(data.Slice(offset, sizeof(ulong)));
            sum += (value >> 48) + ((value >> 32) & 0xFFFF) +
                   ((value >> 16) & 0xFFFF) + (value & 0xFFFF);
            offset += sizeof(ulong);
        }

        while (offset + 1 < data.Length)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
            offset += 2;
        }

        if (offset < data.Length)
            sum += (uint)data[offset] << 8;

        return sum;
    }

    internal static ushort Complete(ulong sum)
    {
        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }
}
