namespace TunRelayClient
{
    internal enum DataChannelProtocol
    {
        Tls,
        Tcp
    }

    internal static class DataChannelProtocolCodec
    {
        public static string[] SupportedWireValues { get; } = ["tls", "tcp"];

        public static string ToWire(DataChannelProtocol protocol)
            => protocol switch
            {
                DataChannelProtocol.Tls => "tls",
                DataChannelProtocol.Tcp => "tcp",
                _ => throw new UnsupportedDataChannelProtocolException(protocol.ToString())
            };

        public static DataChannelProtocol Parse(string? value)
        {
            if (string.IsNullOrWhiteSpace(value) || string.Equals(value, "tls", StringComparison.OrdinalIgnoreCase))
                return DataChannelProtocol.Tls;
            if (string.Equals(value, "tcp", StringComparison.OrdinalIgnoreCase))
                return DataChannelProtocol.Tcp;

            throw new UnsupportedDataChannelProtocolException(value);
        }
    }

    internal class DataChannelConfigurationException : Exception
    {
        public DataChannelConfigurationException(string message)
            : base(message)
        {
        }
    }

    internal sealed class UnsupportedDataChannelProtocolException : DataChannelConfigurationException
    {
        public UnsupportedDataChannelProtocolException(string? protocol)
            : base($"Unsupported data channel protocol: {protocol ?? "<null>"}")
        {
        }
    }
}
