using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Newtonsoft.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace TunRelayServer
{
    sealed class Client : IDisposable
    {
        public Client(
            TcpClient controlTcp,
            SslStream controlSsl,
            TcpClient txTcp,
            SslStream txSsl,
            TcpClient rxTcp,
            SslStream rxSsl)
        {
            ControlTcp = controlTcp;
            ControlSsl = controlSsl;
            TxTcp = txTcp;
            TxSsl = txSsl;
            RxTcp = rxTcp;
            RxSsl = rxSsl;
        }

        public TcpClient ControlTcp { get; }
        public SslStream ControlSsl { get; }
        public TcpClient TxTcp { get; }
        public SslStream TxSsl { get; }
        public TcpClient RxTcp { get; }
        public SslStream RxSsl { get; }

        public void Dispose()
        {
            ControlSsl.Dispose();
            ControlTcp.Dispose();
            TxSsl.Dispose();
            TxTcp.Dispose();
            RxSsl.Dispose();
            RxTcp.Dispose();
        }
    }

    static class ServerNet
    {
        static ILogger _logger;
        sealed class AuthenticationRequest
        {
            public string ClientID { get; set; } = "";
            public long Timestamp { get; set; }
            public string Sign { get; set; } = "";
        }

        public static void Init(ILogger logger)
        {
            _logger = logger;
        }
        public static async Task<Client> AcceptAuthenticatedClientAsync(
            TcpListener listener,
            X509Certificate2 cert,
            TunRelayConfig config,
            CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                _logger?.LogInformation("等待控制连接...");
                var controlTcp = await listener.AcceptTcpClientAsync(ct);
                controlTcp.NoDelay = true;
                var controlSsl = new SslStream(controlTcp.GetStream(), false);
                await controlSsl.AuthenticateAsServerAsync(cert, false, false);
                _logger?.LogInformation($"控制连接来自 {controlTcp.Client.RemoteEndPoint}");

                _logger?.LogInformation("等待TX数据连接...");
                var txTcp = await listener.AcceptTcpClientAsync(ct);
                txTcp.NoDelay = true;
                var txSsl = new SslStream(txTcp.GetStream(), false);
                await txSsl.AuthenticateAsServerAsync(cert, false, false);
                _logger?.LogInformation($"TX数据连接来自 {txTcp.Client.RemoteEndPoint}");

                _logger?.LogInformation("等待RX数据连接...");
                var rxTcp = await listener.AcceptTcpClientAsync(ct);
                rxTcp.NoDelay = true;
                var rxSsl = new SslStream(rxTcp.GetStream(), false);
                await rxSsl.AuthenticateAsServerAsync(cert, false, false);
                _logger?.LogInformation($"RX数据连接来自 {rxTcp.Client.RemoteEndPoint}");

                var client = new Client(controlTcp, controlSsl, txTcp, txSsl, rxTcp, rxSsl);
                bool authenticated = false;
                try
                {
                    _logger?.LogInformation("[AUTH] 等待客户端认证...");
                    authenticated = await AuthenticateClientAsync(controlSsl, config, ct);
                    await SendAsync(controlSsl, Encoding.UTF8.GetBytes(authenticated ? "Success" : "Failed"), ct);
                    _logger?.LogInformation($"[AUTH] 已返回认证结果: {(authenticated ? "Success" : "Failed")}");
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning($"认证异常: {ex.Message}");
                }

                if (authenticated)
                {
                    _logger?.LogInformation($"认证成功: {config.ClientID}");
                    return client;
                }

                _logger?.LogWarning("认证失败，等待下一个客户端");
                client.Dispose();
            }

            throw new OperationCanceledException(ct);
        }

        static async Task<bool> AuthenticateClientAsync(SslStream controlSsl, TunRelayConfig config, CancellationToken ct)
        {
            using var data = await ReceiveAsync(controlSsl, ct);
            string json = Encoding.UTF8.GetString(data.Buffer, 0, data.Length);
            var request = JsonConvert.DeserializeObject<AuthenticationRequest>(json);
            if (request == null)
            {
                _logger?.LogWarning("[AUTH] 失败: 请求格式无效");
                return false;
            }

            _logger?.LogInformation($"[AUTH] 收到认证 ClientID={request.ClientID}, Timestamp={request.Timestamp}");

            if (!string.Equals(request.ClientID, config.ClientID, StringComparison.Ordinal))
            {
                _logger?.LogWarning($"[AUTH] 失败: ClientID 不匹配，期望={config.ClientID}");
                return false;
            }

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (Math.Abs(now - request.Timestamp) > 300)
            {
                _logger?.LogWarning($"[AUTH] 失败: Timestamp 超时，now={now}");
                return false;
            }

            string expectedSign = ComputeSign(config.Secret, request.ClientID, request.Timestamp);
            if (!FixedTimeHexEquals(expectedSign, request.Sign))
            {
                _logger?.LogWarning("[AUTH] 失败: Sign 不匹配");
                return false;
            }

            return true;
        }

        public static async Task SendAsync(SslStream ssl, ReadOnlyMemory<byte> data, CancellationToken ct)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(4 + data.Length);
            try
            {
                BinaryPrimitives.WriteInt32BigEndian(buffer, data.Length);
                data.CopyTo(buffer.AsMemory(4));
                await ssl.WriteAsync(buffer.AsMemory(0, 4 + data.Length), ct);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        public static async Task<PacketBuffer> ReceiveAsync(SslStream ssl, CancellationToken ct)
        {
            var lenBuf = ArrayPool<byte>.Shared.Rent(4);
            int totalLen;
            try
            {
                await ssl.ReadExactlyAsync(lenBuf.AsMemory(0, 4), ct);
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
                await ssl.ReadExactlyAsync(payload.Memory, ct);
                return payload;
            }
            catch
            {
                payload.Dispose();
                throw;
            }
        }

        public static string GenerateSecret()
        {
            return Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        }

        public static X509Certificate2 GenerateSelfSignedCertificate(string serverName)
        {
            using var rsa = RSA.Create(2048);

            var req = new CertificateRequest(
                "CN=TunRelayServer",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            if (!string.IsNullOrWhiteSpace(serverName))
            {
                var sanBuilder = new SubjectAlternativeNameBuilder();
                if (IPAddress.TryParse(serverName, out var ipAddress))
                    sanBuilder.AddIpAddress(ipAddress);
                else
                    sanBuilder.AddDnsName(serverName);

                req.CertificateExtensions.Add(sanBuilder.Build());
            }

            // 服务器认证用途
            req.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection
                    {
                new Oid("1.3.6.1.5.5.7.3.1") // Server Authentication
                    },
                    false));

            // 数字签名
            req.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature |
                    X509KeyUsageFlags.KeyEncipherment,
                    false));

            var cert = req.CreateSelfSigned(
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddYears(10));

            return cert;
        }

        static string ComputeSign(string secret, string clientId, long timestamp)
        {
            byte[] key = Encoding.UTF8.GetBytes(secret);
            byte[] msg = Encoding.UTF8.GetBytes($"{clientId}:{timestamp}");
            using var hmac = new HMACSHA256(key);
            return Convert.ToHexString(hmac.ComputeHash(msg));
        }

        static bool FixedTimeHexEquals(string expectedHex, string actualHex)
        {
            try
            {
                byte[] expected = Convert.FromHexString(expectedHex);
                byte[] actual = Convert.FromHexString(actualHex);
                return expected.Length == actual.Length
                    && CryptographicOperations.FixedTimeEquals(expected, actual);
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }

    static class RawSender
    {
        static ILogger _logger;

        [DllImport("libc.so.6", EntryPoint = "socket")]
        static extern int socket(int domain, int type, int protocol);

        [DllImport("libc.so.6", EntryPoint = "setsockopt")]
        static extern int setsockopt(int sockfd, int level, int optname, ref int optval, uint optlen);

        [DllImport("libc.so.6", EntryPoint = "sendto")]
        static extern int sendto(int sockfd, byte[] buf, int len, int flags, ref SockAddrIn addr, int addrlen);

        [StructLayout(LayoutKind.Sequential)]
        struct SockAddrIn
        {
            public ushort sin_family;
            public ushort sin_port;
            public uint sin_addr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] sin_zero;
        }

        static int _fd = -1;

        public static void Init(ILogger logger)
        {
            _logger = logger;
            _fd = socket(2, 3, 255);
            if (_fd < 0) throw new Exception("创建 Raw Socket 失败，需要 root 权限");
            int one = 1;
            setsockopt(_fd, 0, 3, ref one, 4);
            _logger?.LogInformation("Raw Socket 已初始化");
        }

        public static void Send(PacketBuffer packet)
        {
            if (packet.Length < 20) return;

            uint dstAddr = BitConverter.ToUInt32(packet.Buffer, 16);
            var addr = new SockAddrIn
            {
                sin_family = 2,
                sin_port = 0,
                sin_addr = dstAddr,
                sin_zero = new byte[8]
            };

            int sent = sendto(_fd, packet.Buffer, packet.Length, 0, ref addr, Marshal.SizeOf<SockAddrIn>());
            if (sent < 0)
                _logger?.LogWarning($"[RAW] 发送失败 len={packet.Length}");
        }
    }
}
