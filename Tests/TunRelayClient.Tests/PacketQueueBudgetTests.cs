using Xunit;

namespace TunRelayClient.Tests;

public sealed class PacketQueueBudgetTests
{
    [Theory]
    [InlineData(1, 1536)]
    [InlineData(4, 384)]
    [InlineData(16, 96)]
    public void CapacityPerChannel_StaysWithinQueueBudget(int channels, int expectedCapacity)
    {
        int capacity = PacketQueueBudget.CapacityPerChannel(channels);

        Assert.Equal(expectedCapacity, capacity);
        Assert.True((long)capacity * channels * PacketQueueBudget.MaxPacketBytes
            <= PacketQueueBudget.QueueBudgetBytes);
    }

    [Fact]
    public void CapacityPerChannel_RejectsNonPositiveChannelCount()
        => Assert.Throws<ArgumentOutOfRangeException>(() => PacketQueueBudget.CapacityPerChannel(0));
}
