using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace TunRelayServer
{
    // 已认证控制连接 + 生成的一次性 sessionId
    sealed class ControlChannel : IDisposable
    {
        public ControlChannel(TcpClient tcp, SslStream ssl, string sessionId)
        {
            Tcp = tcp;
            Ssl = ssl;
            SessionId = sessionId;
        }

        public TcpClient Tcp { get; }
        public SslStream Ssl { get; }
        public string SessionId { get; }

        public void Dispose()
        {
            Ssl.Dispose();
            Tcp.Dispose();
        }
    }

    // 一个会话: 控制连接 + N 条上行(client->server, server 读) + N 条下行(server->client, server 写)
    sealed class Session : IDisposable
    {
        public Session(ControlChannel control, Stream[] txStreams, Stream[] rxStreams, List<TcpClient> dataTcp, List<Stream> dataStreams)
        {
            Control = control;
            TxStreams = txStreams;
            RxStreams = rxStreams;
            _dataTcp = dataTcp;
            _dataStreams = dataStreams;
        }

        public ControlChannel Control { get; }
        public Stream[] TxStreams { get; }
        public Stream[] RxStreams { get; }

        private readonly List<TcpClient> _dataTcp;
        private readonly List<Stream> _dataStreams;

        public void Dispose()
        {
            foreach (var stream in _dataStreams) stream.Dispose();
            foreach (var t in _dataTcp) t.Dispose();
            Control.Dispose();
        }
    }

    sealed class DataChannelHandshake
    {
        public string SessionId { get; set; } = "";
        public string Role { get; set; } = "";
        public int Index { get; set; }
    }

    static class ServerNet
    {
        static ILogger _logger;
        static string _configPath = "config.json";

        public static void Init(ILogger logger, string configPath)
        {
            _logger = logger;
            _configPath = configPath;
        }

        // 接受一条控制连接并完成认证;成功则生成 sessionId 一并返回。失败则继续等待下一个。
        public static async Task<ControlChannel> AcceptControlAsync(
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

                bool authenticated = false;
                try
                {
                    await controlSsl.AuthenticateAsServerAsync(cert, false, false);
                    _logger?.LogInformation($"控制连接来自 {controlTcp.Client.RemoteEndPoint}");

                    using var authData = await ReceiveAsync(controlSsl, ct);
                    string authJson = Encoding.UTF8.GetString(authData.Buffer, 0, authData.Length);
                    var provisioningRequest = JsonSerializer.Deserialize(
                        authJson,
                        TunRelayJsonContext.Default.CredentialProvisioningRequest);

                    if (provisioningRequest != null
                        && string.Equals(provisioningRequest.Mode, "AutoCredentials", StringComparison.Ordinal))
                    {
                        var protocol = DataChannelProtocolCodec.Parse(config.Protocol);
                        if (!DataChannelProtocolCodec.IsSupported(provisioningRequest.SupportedProtocols, protocol))
                        {
                            string error = $"UnsupportedProtocol:{DataChannelProtocolCodec.ToWire(protocol)}";
                            await SendCredentialProvisioningResponseAsync(controlSsl, "Failed", "", error, ct);
                        }
                        else
                        {
                            authenticated = await ProvisionCredentialsAsync(controlSsl, config, provisioningRequest, ct);
                        }
                    }
                    else
                    {
                        _logger?.LogInformation("[AUTH] 等待客户端认证...");
                        var request = JsonSerializer.Deserialize(
                            authJson,
                            TunRelayJsonContext.Default.AuthenticationRequest);
                        authenticated = AuthenticateClient(request, config);
                        string response = authenticated ? "Success" : "Failed";
                        var protocol = DataChannelProtocolCodec.Parse(config.Protocol);
                        if (authenticated && !DataChannelProtocolCodec.IsSupported(request?.SupportedProtocols, protocol))
                        {
                            authenticated = false;
                            response = $"UnsupportedProtocol:{DataChannelProtocolCodec.ToWire(protocol)}";
                        }
                        await SendAsync(controlSsl, Encoding.UTF8.GetBytes(response), ct);
                        _logger?.LogInformation($"[AUTH] 已返回认证结果: {(authenticated ? "Success" : "Failed")}");
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning($"认证异常: {ex.Message}");
                }

                if (authenticated)
                {
                    _logger?.LogInformation($"认证成功: {config.ClientID}");
                    string sessionId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
                    return new ControlChannel(controlTcp, controlSsl, sessionId);
                }

                _logger?.LogWarning("认证失败，等待下一个客户端");
                controlSsl.Dispose();
                controlTcp.Dispose();
            }

            throw new OperationCanceledException(ct);
        }

        static async Task<bool> ProvisionCredentialsAsync(
            SslStream controlSsl,
            TunRelayConfig config,
            CredentialProvisioningRequest request,
            CancellationToken ct)
        {
            if (!config.AutoCredentials)
            {
                _logger?.LogWarning("[AUTH] 拒绝自动配置: AutoCredentials 未开启");
                await SendCredentialProvisioningResponseAsync(controlSsl, "Failed", "", "", ct);
                return false;
            }

            if (string.IsNullOrWhiteSpace(request.ClientID))
            {
                _logger?.LogWarning("[AUTH] 拒绝自动配置: ClientID 为空");
                await SendCredentialProvisioningResponseAsync(controlSsl, "Failed", "", "", ct);
                return false;
            }

            if (string.IsNullOrWhiteSpace(config.Secret))
                config.Secret = GenerateSecret();

            config.ClientID = request.ClientID;
            config.AutoCredentials = false;
            ConfigManager.Save(_configPath, config);

            await SendCredentialProvisioningResponseAsync(controlSsl, "Success", config.Secret, "", ct);
            _logger?.LogWarning($"[AUTH] 已为客户端 {config.ClientID} 自动配置凭据，AutoCredentials 已关闭");
            return true;
        }

        static async Task SendCredentialProvisioningResponseAsync(
            SslStream controlSsl,
            string status,
            string secret,
            string error,
            CancellationToken ct)
        {
            var json = JsonSerializer.Serialize(
                new CredentialProvisioningResponse { Status = status, Secret = secret, Error = error },
                TunRelayJsonContext.Default.CredentialProvisioningResponse);
            await SendAsync(controlSsl, Encoding.UTF8.GetBytes(json), ct);
        }

        // 组装 N 条上行 + N 条下行数据连接: 打开所选传输后读取 {SessionId, Role, Index},校验 sessionId 后归位。
        // 带超时;未在期限内集齐则视为失败(抛异常,由上层重来)。
        public static async Task<Session> AssembleDataConnectionsAsync(
            TcpListener listener,
            X509Certificate2 cert,
            ControlChannel control,
            DataChannelProtocol protocol,
            int uplink,
            int downlink,
            CancellationToken ct)
        {
            var txStreams = new Stream[uplink];
            var rxStreams = new Stream[downlink];
            var dataTcp = new List<TcpClient>(uplink + downlink);
            var dataStreams = new List<Stream>(uplink + downlink);
            var adapter = DataChannelServerAdapter.Create(protocol);
            int got = 0, need = uplink + downlink;

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));

            try
            {
                while (got < need)
                {
                    var tcp = await listener.AcceptTcpClientAsync(timeoutCts.Token);
                    tcp.NoDelay = true;
                    Stream? stream = null;
                    try
                    {
                        stream = await adapter.OpenAsync(tcp, cert, timeoutCts.Token);
                        using var data = await ReceiveAsync(stream, timeoutCts.Token);
                        var hs = JsonSerializer.Deserialize(
                            Encoding.UTF8.GetString(data.Buffer, 0, data.Length),
                            TunRelayJsonContext.Default.DataChannelHandshake);

                        if (hs == null
                            || !FixedTimeHexEquals(hs.SessionId, control.SessionId)
                            || hs.Index < 0
                            || (hs.Role != "tx" && hs.Role != "rx")
                            || (hs.Role == "tx" && hs.Index >= uplink)
                            || (hs.Role == "rx" && hs.Index >= downlink)
                            || (hs.Role == "tx" && txStreams[hs.Index] != null)
                            || (hs.Role == "rx" && rxStreams[hs.Index] != null))
                        {
                            _logger?.LogWarning($"[ASM] 拒绝数据连接 (sessionId/role/index 非法或重复)");
                            stream.Dispose();
                            tcp.Dispose();
                            continue;
                        }

                        if (hs.Role == "tx") txStreams[hs.Index] = stream;
                        else rxStreams[hs.Index] = stream;
                        dataTcp.Add(tcp);
                        dataStreams.Add(stream);
                        got++;
                        _logger?.LogInformation($"[ASM] 数据连接 {hs.Role}#{hs.Index} 就位 ({got}/{need})");
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        _logger?.LogWarning($"[ASM] 数据连接握手失败: {ex.Message}");
                        stream?.Dispose();
                        tcp.Dispose();
                    }
                }

                _logger?.LogInformation($"会话已集齐: 上行 {uplink} 条, 下行 {downlink} 条");
                return new Session(control, txStreams, rxStreams, dataTcp, dataStreams);
            }
            catch
            {
                foreach (var stream in dataStreams) stream.Dispose();
                foreach (var t in dataTcp) t.Dispose();
                throw;
            }
        }

        static bool AuthenticateClient(AuthenticationRequest? request, TunRelayConfig config)
        {
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

        public static async Task SendAsync(Stream stream, ReadOnlyMemory<byte> data, CancellationToken ct)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(4 + data.Length);
            try
            {
                BinaryPrimitives.WriteInt32BigEndian(buffer, data.Length);
                data.CopyTo(buffer.AsMemory(4));
                await stream.WriteAsync(buffer.AsMemory(0, 4 + data.Length), ct);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        public static async Task<PacketBuffer> ReceiveAsync(Stream stream, CancellationToken ct)
        {
            var lenBuf = ArrayPool<byte>.Shared.Rent(4);
            int totalLen;
            try
            {
                await stream.ReadExactlyAsync(lenBuf.AsMemory(0, 4), ct);
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
                await stream.ReadExactlyAsync(payload.Memory, ct);
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
        static extern int sendto(int sockfd, IntPtr buf, int len, int flags, ref SockAddrIn addr, int addrlen);

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

        public static unsafe void Send(ReadOnlyMemory<byte> packet)
        {
            if (packet.Length < 20) return;

            var span = packet.Span;
            // 取目的 IP(packet[16..20]),保持原始网络字节序写入 sin_addr
            uint dstAddr = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(16, 4));
            var addr = new SockAddrIn
            {
                sin_family = 2,
                sin_port = 0,
                sin_addr = dstAddr,
                sin_zero = new byte[8]
            };

            int sent;
            using (var handle = packet.Pin())
                sent = sendto(_fd, (IntPtr)handle.Pointer, packet.Length, 0, ref addr, Marshal.SizeOf<SockAddrIn>());

            if (sent < 0)
            {
                _logger?.LogWarning($"[RAW] 发送失败 len={packet.Length}");
                TunnelStats.IncrementSinkWriteFailures();
            }
        }
    }
}
