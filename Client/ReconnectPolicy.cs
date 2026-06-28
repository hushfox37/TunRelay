namespace TunRelayClient
{
    internal sealed class ReconnectPolicy
    {
        public ReconnectPolicy(TimeSpan delay, int maxAttempts)
        {
            Delay = delay;
            MaxAttempts = maxAttempts;
        }

        public TimeSpan Delay { get; }
        public int MaxAttempts { get; }
        public int Attempts { get; private set; }
        public string LimitText => MaxAttempts == 0 ? "无限" : MaxAttempts.ToString();
        public bool HasReachedLimit => MaxAttempts > 0 && Attempts >= MaxAttempts;

        public static ReconnectPolicy FromConfig(TunRelayConfig config)
        {
            // 避免异常配置导致忙重试。
            int delayMs = config.ReconnectDelayMs <= 0 ? 5000 : config.ReconnectDelayMs;
            delayMs = Math.Clamp(delayMs, 100, 600000);
            return new ReconnectPolicy(TimeSpan.FromMilliseconds(delayMs), Math.Max(0, config.MaxReconnectAttempts));
        }

        public int RecordFailure()
        {
            Attempts++;
            return Attempts;
        }

        public void Reset()
        {
            Attempts = 0;
        }
    }
}
