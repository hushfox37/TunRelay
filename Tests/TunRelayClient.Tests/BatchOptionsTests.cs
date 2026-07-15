using TunRelayClient;
using Xunit;

namespace TunRelayClient.Tests;

public sealed class BatchOptionsTests
{
    [Fact]
    public void AdaptiveBatchingDefaultsToDisabled()
    {
        Assert.False(new TunRelayConfig().AdaptiveBatching);
        Assert.False(new BatchOptions(1, 65_536, 32).AdaptiveBatching);
    }

    [Fact]
    public void AdaptiveBatchingCanBeChangedAtRuntime()
    {
        var options = new BatchOptions(1, 65_536, 32, adaptiveBatching: true);
        Assert.True(options.AdaptiveBatching);

        options.SetAdaptiveBatching(false);

        Assert.False(options.AdaptiveBatching);
        Assert.Equal(1, options.DelayMs);
        Assert.Equal(65_536, options.MaxBytes);
        Assert.Equal(32, options.MaxPackets);
    }
}
