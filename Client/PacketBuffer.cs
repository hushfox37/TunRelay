using System.Buffers;

namespace VirtualIPClient
{
    public sealed class PacketBuffer : IDisposable
    {
        private bool disposed;

        private PacketBuffer(byte[] buffer, int length)
        {
            Buffer = buffer;
            Length = length;
        }

        public byte[] Buffer { get; private set; }

        public int Length { get; private set; }

        public Memory<byte> Memory => Buffer.AsMemory(0, Length);

        public ReadOnlyMemory<byte> ReadOnlyMemory => Buffer.AsMemory(0, Length);

        public static PacketBuffer Rent(int length)
        {
            return new PacketBuffer(ArrayPool<byte>.Shared.Rent(length), length);
        }

        public void Dispose()
        {
            if (disposed) return;
            ArrayPool<byte>.Shared.Return(Buffer);
            Buffer = Array.Empty<byte>();
            Length = 0;
            disposed = true;
        }
    }
}
