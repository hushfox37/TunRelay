namespace TunRelayClient;

internal static class PacketQueueBudget
{
    // 将 128 MiB 进程缓冲预算中的 32 MiB 留给 Pipe/TLS/当前 batch，
    // 包队列按最大 IPv4 包计算，避免高 MTU 时队列容量失控。
    internal const int ProcessBufferBudgetBytes = 128 * 1024 * 1024;
    internal const int QueueBudgetBytes = 96 * 1024 * 1024;
    internal const int MaxPacketBytes = 64 * 1024;

    internal static int CapacityPerChannel(int channelCount)
    {
        if (channelCount <= 0)
            throw new ArgumentOutOfRangeException(nameof(channelCount));

        return Math.Max(64, QueueBudgetBytes / channelCount / MaxPacketBytes);
    }
}
