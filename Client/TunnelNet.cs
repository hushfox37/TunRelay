using System.Buffers;
using System.Buffers.Binary;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TunRelayClient
{
    public class TunnelNet
    {
        private readonly string ServerIP;
        private readonly int ServerPort;
        private SslStream ControlConnectionSsl;
        private TcpClient ControlConnectionTcp;
        private SslStream TxConnectionSsl;
        private TcpClient TxConnectionTcp;
        private SslStream RxConnectionSsl;
        private TcpClient RxConnectionTcp;

        public TunnelNet(string serverIP, int serverPort)
        {
            ServerIP = serverIP;
            ServerPort = serverPort;
        }

        public async Task ConnectAsync()
        {
            ControlConnectionTcp = new TcpClient();
            await ControlConnectionTcp.ConnectAsync(ServerIP, ServerPort);
            ControlConnectionTcp.NoDelay = true;
            ControlConnectionSsl = new SslStream(ControlConnectionTcp.GetStream(), false, ValidateServerCertificate, null);
            await ControlConnectionSsl.AuthenticateAsClientAsync(ServerIP);

            TxConnectionTcp = new TcpClient();
            await TxConnectionTcp.ConnectAsync(ServerIP, ServerPort);
            TxConnectionTcp.NoDelay = true;
            TxConnectionSsl = new SslStream(TxConnectionTcp.GetStream(), false, ValidateServerCertificate, null);
            await TxConnectionSsl.AuthenticateAsClientAsync(ServerIP);

            RxConnectionTcp = new TcpClient();
            await RxConnectionTcp.ConnectAsync(ServerIP, ServerPort);
            RxConnectionTcp.NoDelay = true;
            RxConnectionSsl = new SslStream(RxConnectionTcp.GetStream(), false, ValidateServerCertificate, null);
            await RxConnectionSsl.AuthenticateAsClientAsync(ServerIP);
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

        // 数据通道 batch 收发直接基于这两个 SslStream 建立 PipeWriter/PipeReader
        public Stream TxStream => TxConnectionSsl;
        public Stream RxStream => RxConnectionSsl;

        public void Close()
        {
            ControlConnectionSsl?.Dispose();
            ControlConnectionTcp?.Dispose();
            TxConnectionSsl?.Dispose();
            TxConnectionTcp?.Dispose();
            RxConnectionSsl?.Dispose();
            RxConnectionTcp?.Dispose();
        }
    }
}
