using System.Buffers.Binary;

namespace TunRelayServer;

internal static class NfQueueNetlinkMetadata
{
    private const int NetlinkHeaderLength = 16;
    private const int NfgenmsgLength = 4;
    private const ushort AttributeTypeMask = 0x3fff;
    private const ushort PacketHeaderAttribute = 1;
    private const ushort CaptureLengthAttribute = 13;

    public static bool TryGetOriginalLength(
        ReadOnlySpan<byte> batch,
        uint packetId,
        out uint originalLength)
    {
        int messageOffset = 0;
        while (messageOffset + NetlinkHeaderLength + NfgenmsgLength <= batch.Length)
        {
            uint messageLengthValue = BinaryPrimitives.ReadUInt32LittleEndian(batch.Slice(messageOffset, 4));
            if (messageLengthValue < NetlinkHeaderLength + NfgenmsgLength
                || messageLengthValue > int.MaxValue)
                break;

            int messageLength = (int)messageLengthValue;
            int messageEnd = messageOffset + messageLength;
            if (messageEnd > batch.Length)
                break;

            uint? currentPacketId = null;
            uint? currentOriginalLength = null;
            int attributeOffset = messageOffset + NetlinkHeaderLength + NfgenmsgLength;
            while (attributeOffset + 4 <= messageEnd)
            {
                ushort attributeLength = BinaryPrimitives.ReadUInt16LittleEndian(batch.Slice(attributeOffset, 2));
                ushort attributeType = (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(batch.Slice(attributeOffset + 2, 2)) & AttributeTypeMask);
                if (attributeLength < 4 || attributeOffset + attributeLength > messageEnd)
                    break;

                ReadOnlySpan<byte> value = batch.Slice(attributeOffset + 4, attributeLength - 4);
                if (attributeType == PacketHeaderAttribute && value.Length >= 4)
                    currentPacketId = BinaryPrimitives.ReadUInt32BigEndian(value);
                else if (attributeType == CaptureLengthAttribute && value.Length >= 4)
                    currentOriginalLength = BinaryPrimitives.ReadUInt32BigEndian(value);

                attributeOffset += Align(attributeLength);
            }

            if (currentPacketId == packetId && currentOriginalLength is uint length)
            {
                originalLength = length;
                return true;
            }

            messageOffset += Align(messageLength);
        }

        originalLength = 0;
        return false;
    }

    private static int Align(int length) => (length + 3) & ~3;
}
