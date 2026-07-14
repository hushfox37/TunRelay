namespace TunRelayServer
{
    internal enum DataChannelProtocol
    {
        Tls,
        Tcp
    }

    internal static class DataChannelProtocolCodec
    {
        public static DataChannelProtocol Parse(string? value)
        {
            if (string.IsNullOrWhiteSpace(value) || string.Equals(value, "tls", StringComparison.OrdinalIgnoreCase))
                return DataChannelProtocol.Tls;
            if (string.Equals(value, "tcp", StringComparison.OrdinalIgnoreCase))
                return DataChannelProtocol.Tcp;

            throw new InvalidOperationException($"Protocol must be 'tls' or 'tcp', got '{value}'");
        }

        public static string ToWire(DataChannelProtocol protocol)
            => protocol switch
            {
                DataChannelProtocol.Tls => "tls",
                DataChannelProtocol.Tcp => "tcp",
                _ => throw new InvalidOperationException($"Unsupported protocol: {protocol}")
            };

        public static bool IsSupported(string[]? values, DataChannelProtocol protocol)
        {
            if (values == null || values.Length == 0)
                return protocol == DataChannelProtocol.Tls;

            string expected = ToWire(protocol);
            return values.Any(value => string.Equals(value, expected, StringComparison.OrdinalIgnoreCase));
        }
    }
}
