using System.Buffers;

namespace TunRelayClient
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

        /// <summary>
        /// 调整有效长度。底层数组容量保持不变(可大于 length),用于"租大 buffer 直接读入,再设置实际长度"的零二次拷贝场景。
        /// </summary>
        public void SetLength(int length)
        {
            if (length < 0 || length > Buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(length));
            Length = length;
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
