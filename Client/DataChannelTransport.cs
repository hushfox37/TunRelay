using System.Net.Security;
using System.Net.Sockets;

namespace TunRelayClient
{
    internal interface IDataChannelClientAdapter
    {
        Task<Stream> OpenAsync(TcpClient tcp, CancellationToken ct);
    }

    internal static class DataChannelClientAdapter
    {
        public static IDataChannelClientAdapter Create(
            DataChannelProtocol protocol,
            string serverName,
            RemoteCertificateValidationCallback certificateValidation)
            => protocol switch
            {
                DataChannelProtocol.Tls => new TlsDataChannelClientAdapter(serverName, certificateValidation),
                DataChannelProtocol.Tcp => TcpDataChannelClientAdapter.Instance,
                _ => throw new UnsupportedDataChannelProtocolException(protocol.ToString())
            };
    }

    internal sealed class TcpDataChannelClientAdapter : IDataChannelClientAdapter
    {
        public static TcpDataChannelClientAdapter Instance { get; } = new();

        private TcpDataChannelClientAdapter()
        {
        }

        public Task<Stream> OpenAsync(TcpClient tcp, CancellationToken ct)
            => Task.FromResult<Stream>(tcp.GetStream());
    }

    internal sealed class TlsDataChannelClientAdapter : IDataChannelClientAdapter
    {
        private readonly string _serverName;
        private readonly RemoteCertificateValidationCallback _certificateValidation;

        public TlsDataChannelClientAdapter(
            string serverName,
            RemoteCertificateValidationCallback certificateValidation)
        {
            _serverName = serverName;
            _certificateValidation = certificateValidation;
        }

        public async Task<Stream> OpenAsync(TcpClient tcp, CancellationToken ct)
        {
            var ssl = new SslStream(tcp.GetStream(), false, _certificateValidation);
            try
            {
                await ssl.AuthenticateAsClientAsync(
                    new SslClientAuthenticationOptions { TargetHost = _serverName },
                    ct);
                return ssl;
            }
            catch
            {
                ssl.Dispose();
                throw;
            }
        }
    }
}
