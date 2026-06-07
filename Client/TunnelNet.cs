using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Buffers.Binary;
using System.Buffers;
using System.Text;

namespace VirtualIPClient
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
            this.ServerIP = serverIP;
            this.ServerPort = serverPort;
        }
        public async Task ConnectAsync()
        {   // 建立控制连接
            this.ControlConnectionTcp = new TcpClient();
            await this.ControlConnectionTcp.ConnectAsync(this.ServerIP, this.ServerPort);
            this.ControlConnectionTcp.NoDelay = true;
            this.ControlConnectionSsl = new SslStream(this.ControlConnectionTcp.GetStream(), false, (_, _, _, _) => true, null);
            await this.ControlConnectionSsl.AuthenticateAsClientAsync(this.ServerIP);
            // 建立数据连接
            this.TxConnectionTcp = new TcpClient();
            await this.TxConnectionTcp.ConnectAsync(this.ServerIP, this.ServerPort);
            this.TxConnectionTcp.NoDelay = true;
            this.TxConnectionSsl = new SslStream(this.TxConnectionTcp.GetStream(), false, (_, _, _, _) => true, null);
            await this.TxConnectionSsl.AuthenticateAsClientAsync(this.ServerIP);

            this.RxConnectionTcp = new TcpClient();
            await this.RxConnectionTcp.ConnectAsync(this.ServerIP, this.ServerPort);
            this.RxConnectionTcp.NoDelay = true;
            this.RxConnectionSsl = new SslStream(this.RxConnectionTcp.GetStream(), false, (_, _, _, _) => true, null);
            await this.RxConnectionSsl.AuthenticateAsClientAsync(this.ServerIP);
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
            // 接收 4 字节长度头
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
        public async Task SendControlAsync(string data, CancellationToken ct = default)
        {
            await this.SendAsync(Encoding.UTF8.GetBytes(data), this.ControlConnectionSsl, ct);
        }

        public async Task<string> ReceiveControlAsync(CancellationToken ct = default)
        {
            using var data = await this.ReceivePacketAsync(this.ControlConnectionSsl, ct);
            return Encoding.UTF8.GetString(data.Buffer, 0, data.Length);
        }

        public async Task SendDataAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
        {
            await this.SendAsync(data, this.TxConnectionSsl, ct);
        }

        public async Task<PacketBuffer> ReceiveDataAsync(CancellationToken ct = default)
        {
            return await this.ReceivePacketAsync(this.RxConnectionSsl, ct);
        }

        public void Close()
        {
            this.ControlConnectionSsl?.Dispose();
            this.ControlConnectionTcp?.Dispose();
            this.TxConnectionSsl?.Dispose();
            this.TxConnectionTcp?.Dispose();
            this.RxConnectionSsl?.Dispose();
            this.RxConnectionTcp?.Dispose();
        }
    }
}
