using System.Buffers;
using System.Buffers.Binary;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace TunRelayClient
{
    public class TunnelNet
    {
        private readonly string ServerIP;
        private readonly int ServerPort;

        private SslStream ControlConnectionSsl = null!;
        private TcpClient ControlConnectionTcp = null!;

        // 多连接: 上行(client->server, role=tx) 与 下行(server->client, role=rx) 各 N 条。
        private TcpClient[] _txTcp = Array.Empty<TcpClient>();
        private SslStream[] _txSsl = Array.Empty<SslStream>();
        private TcpClient[] _rxTcp = Array.Empty<TcpClient>();
        private SslStream[] _rxSsl = Array.Empty<SslStream>();

        public TunnelNet(string serverIP, int serverPort)
        {
            ServerIP = serverIP;
            ServerPort = serverPort;
        }

        // 先只建立控制连接,认证 + 接收下发配置(含并行连接数与 sessionId)后再建数据连接。
        public async Task ConnectControlAsync(CancellationToken ct = default)
        {
            ControlConnectionTcp = new TcpClient();
            await ControlConnectionTcp.ConnectAsync(ServerIP, ServerPort, ct);
            ControlConnectionTcp.NoDelay = true;
            ControlConnectionSsl = new SslStream(ControlConnectionTcp.GetStream(), false, ValidateServerCertificate, null);
            await ControlConnectionSsl.AuthenticateAsClientAsync(ServerIP);
        }

        // 按服务端下发的数量建立 N 条上行 + N 条下行数据连接,每条先发握手头 {SessionId, Role, Index}。
        public async Task ConnectDataChannelsAsync(int uplink, int downlink, string sessionId, CancellationToken ct = default)
        {
            _txTcp = new TcpClient[uplink];
            _txSsl = new SslStream[uplink];
            for (int i = 0; i < uplink; i++)
                (_txTcp[i], _txSsl[i]) = await ConnectOneDataAsync(sessionId, "tx", i, ct);

            _rxTcp = new TcpClient[downlink];
            _rxSsl = new SslStream[downlink];
            for (int i = 0; i < downlink; i++)
                (_rxTcp[i], _rxSsl[i]) = await ConnectOneDataAsync(sessionId, "rx", i, ct);
        }

        private async Task<(TcpClient, SslStream)> ConnectOneDataAsync(string sessionId, string role, int index, CancellationToken ct)
        {
            var tcp = new TcpClient();
            await tcp.ConnectAsync(ServerIP, ServerPort, ct);
            tcp.NoDelay = true;
            var ssl = new SslStream(tcp.GetStream(), false, ValidateServerCertificate, null);
            await ssl.AuthenticateAsClientAsync(ServerIP);

            var handshake = JsonSerializer.Serialize(
                new DataChannelHandshake { SessionId = sessionId, Role = role, Index = index },
                TunRelayJsonContext.Default.DataChannelHandshake);
            await SendAsync(Encoding.UTF8.GetBytes(handshake), ssl, ct);
            return (tcp, ssl);
        }

        private async Task SendAsync(ReadOnlyMemory<byte> data, SslStream sslStream, CancellationToken ct = default)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(4 + data.Length);
            try
            {
                BinaryPrimitives.WriteInt32BigEndian(buffer, data.Length);
                data.CopyTo(buffer.AsMemory(4));
                await sslStream.WriteAsync(buffer.AsMemory(0, 4 + data.Length), ct);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private async Task<PacketBuffer> ReceivePacketAsync(SslStream sslStream, CancellationToken ct = default)
        {
            byte[] lenBuf = ArrayPool<byte>.Shared.Rent(4);
            int totalLen;
            try
            {
                await sslStream.ReadExactlyAsync(lenBuf.AsMemory(0, 4), ct);
                totalLen = BinaryPrimitives.ReadInt32BigEndian(lenBuf.AsSpan(0, 4));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(lenBuf);
            }

            if (totalLen <= 0 || totalLen > 1024 * 1024)
                throw new InvalidDataException($"Invalid frame length: {totalLen}");

            var payload = PacketBuffer.Rent(totalLen);
            try
            {
                await sslStream.ReadExactlyAsync(payload.Memory, ct);
                return payload;
            }
            catch
            {
                payload.Dispose();
                throw;
            }
        }

        private bool ValidateServerCertificate(
            object sender,
            X509Certificate? certificate,
            X509Chain? chain,
            SslPolicyErrors errors)
        {
            if (certificate == null)
                return false;

            // 允许自签证书的链错误，但证书 SAN 必须匹配配置里的 ServerIp。
            return (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) == SslPolicyErrors.None;
        }

        public async Task SendControlAsync(string data, CancellationToken ct = default)
        {
            await SendAsync(Encoding.UTF8.GetBytes(data), ControlConnectionSsl, ct);
        }

        public async Task<string> ReceiveControlAsync(CancellationToken ct = default)
        {
            using var data = await ReceivePacketAsync(ControlConnectionSsl, ct);
            return Encoding.UTF8.GetString(data.Buffer, 0, data.Length);
        }

        // 数据通道 batch 收发直接基于这些 SslStream 建立 PipeWriter/PipeReader
        public Stream[] TxStreams => _txSsl;
        public Stream[] RxStreams => _rxSsl;

        public void Close()
        {
            ControlConnectionSsl?.Dispose();
            ControlConnectionTcp?.Dispose();
            foreach (var s in _txSsl) s?.Dispose();
            foreach (var t in _txTcp) t?.Dispose();
            foreach (var s in _rxSsl) s?.Dispose();
            foreach (var t in _rxTcp) t?.Dispose();
        }
    }
}
