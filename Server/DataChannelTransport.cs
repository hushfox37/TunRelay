using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace TunRelayServer
{
    internal interface IDataChannelServerAdapter
    {
        Task<Stream> OpenAsync(TcpClient tcp, X509Certificate2 certificate, CancellationToken ct);
    }

    internal static class DataChannelServerAdapter
    {
        public static IDataChannelServerAdapter Create(DataChannelProtocol protocol)
            => protocol switch
            {
                DataChannelProtocol.Tls => TlsDataChannelServerAdapter.Instance,
                DataChannelProtocol.Tcp => TcpDataChannelServerAdapter.Instance,
                _ => throw new InvalidOperationException($"Unsupported protocol: {protocol}")
            };
    }

    internal sealed class TcpDataChannelServerAdapter : IDataChannelServerAdapter
    {
        public static TcpDataChannelServerAdapter Instance { get; } = new();

        private TcpDataChannelServerAdapter()
        {
        }

        public Task<Stream> OpenAsync(TcpClient tcp, X509Certificate2 certificate, CancellationToken ct)
            => Task.FromResult<Stream>(tcp.GetStream());
    }

    internal sealed class TlsDataChannelServerAdapter : IDataChannelServerAdapter
    {
        public static TlsDataChannelServerAdapter Instance { get; } = new();

        private TlsDataChannelServerAdapter()
        {
        }

        public async Task<Stream> OpenAsync(TcpClient tcp, X509Certificate2 certificate, CancellationToken ct)
        {
            var ssl = new SslStream(tcp.GetStream(), false);
            try
            {
                await ssl.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions { ServerCertificate = certificate },
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
