using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Buffers.Binary;
using System.Buffers;
using System.Text;
using System.Threading.Channels;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Newtonsoft.Json;

namespace VirtualIPServer
{
    static class IptablesManager
    {
        static bool _cleared = false;

        static void Run(string args)
        {
            var psi = new ProcessStartInfo("iptables", args)
            {
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var p = Process.Start(psi)!;
            p.WaitForExit();
            if (p.ExitCode != 0)
                Console.WriteLine($"iptables {args} 失败: {p.StandardError.ReadToEnd()}");
        }

        public static void Add(int[] ports)
        {
            var portList = string.Join(",", ports);
            Run($"-I INPUT -p tcp -m multiport --dports {portList} -j NFQUEUE --queue-num 100");
            Run($"-I INPUT -p udp -m multiport --dports {portList} -j NFQUEUE --queue-num 100");
            Console.WriteLine($"iptables 规则已添加: {portList}");
        }

        public static void Remove(int[] ports)
        {
            if (_cleared) return;
            _cleared = true;
            var portList = string.Join(",", ports);
            Run($"-D INPUT -p tcp -m multiport --dports {portList} -j NFQUEUE --queue-num 100");
            Run($"-D INPUT -p udp -m multiport --dports {portList} -j NFQUEUE --queue-num 100");
            Console.WriteLine($"iptables 规则已清理: {portList}");
        }
    }

    static class NFQueue
    {
        [DllImport("libnetfilter_queue.so.1")]
        static extern IntPtr nfq_open();

        [DllImport("libnetfilter_queue.so.1")]
        static extern int nfq_bind_pf(IntPtr h, ushort pf);

        [DllImport("libnetfilter_queue.so.1")]
        static extern IntPtr nfq_create_queue(IntPtr h, ushort num, NfqCallback cb, IntPtr data);

        [DllImport("libnetfilter_queue.so.1")]
        static extern int nfq_set_mode(IntPtr qh, byte mode, uint range);

        [DllImport("libnetfilter_queue.so.1")]
        static extern int nfq_set_verdict(IntPtr qh, uint id, uint verdict, uint dataLen, IntPtr buf);

        [DllImport("libnetfilter_queue.so.1")]
        static extern int nfq_fd(IntPtr h);

        [DllImport("libnetfilter_queue.so.1")]
        static extern int nfq_handle_packet(IntPtr h, byte[] buf, int len);

        [DllImport("libnetfilter_queue.so.1")]
        static extern int nfq_get_payload(IntPtr nfad, out IntPtr data);

        [DllImport("libnetfilter_queue.so.1")]
        static extern IntPtr nfq_get_msg_packet_hdr(IntPtr nfad);

        [DllImport("libc.so.6", EntryPoint = "recv")]
        static extern int recv(int fd, byte[] buf, int len, int flags);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int NfqCallback(IntPtr qh, IntPtr nfmsg, IntPtr nfad, IntPtr data);

        static IntPtr _handle;
        static IntPtr _queueHandle;
        static NfqCallback _callback = null!;

        public static void Start(ushort queueNum, string tunnelIp, Channel<PacketBuffer> txChannel, CancellationToken ct)
        {
            byte[] tunnelIpBytes = IPAddress.Parse(tunnelIp).GetAddressBytes();

            _handle = nfq_open();
            nfq_bind_pf(_handle, 2);

            _callback = (qh, _, nfad, _) =>
            {
                var hdr = nfq_get_msg_packet_hdr(nfad);
                uint id = (uint)IPAddress.NetworkToHostOrder(Marshal.ReadInt32(hdr));

                int len = nfq_get_payload(nfad, out IntPtr payloadPtr);
                if (len > 0)
                {
                    var packet = PacketBuffer.Rent(len);
                    Marshal.Copy(payloadPtr, packet.Buffer, 0, len);

                    if (ShouldForwardToClient(packet, tunnelIpBytes))
                    {
                        if (!txChannel.Writer.TryWrite(packet))
                            packet.Dispose();
                    }
                    else
                    {
                        packet.Dispose();
                    }
                }

                // NF_DROP = 0
                nfq_set_verdict(qh, id, 0, 0, IntPtr.Zero);
                return 0;
            };

            _queueHandle = nfq_create_queue(_handle, queueNum, _callback, IntPtr.Zero);
            nfq_set_mode(_queueHandle, 2, 65535);

            Task.Run(() =>
            {
                int fd = nfq_fd(_handle);
                var buf = new byte[65536];

                while (!ct.IsCancellationRequested)
                {
                    int n = recv(fd, buf, buf.Length, 0);
                    if (n > 0)
                    {
                        nfq_handle_packet(_handle, buf, n);
                    }
                }
            }, ct);

            Console.WriteLine($"NFQUEUE {queueNum} 已启动");
        }

        static bool ShouldForwardToClient(PacketBuffer packet, byte[] tunnelIp)
        {
            // 最小 IPv4 头 20 字节
            if (packet.Length < 20)
                return false;

            // 只处理 IPv4
            if ((packet.Buffer[0] >> 4) != 4)
                return false;

            // 源 IP == TunnelIP，不转发
            if (IsIpEqual(packet, 12, tunnelIp))
                return false;

            // 目标 IP != TunnelIP，不转发
            if (!IsIpEqual(packet, 16, tunnelIp))
                return false;

            // 源 IP == 目标 IP，异常包，不转发
            if (IsSameIp(packet, 12, 16))
                return false;

            return true;
        }

        static bool IsIpEqual(PacketBuffer packet, int offset, byte[] ip)
        {
            return packet.Buffer[offset] == ip[0]
                && packet.Buffer[offset + 1] == ip[1]
                && packet.Buffer[offset + 2] == ip[2]
                && packet.Buffer[offset + 3] == ip[3];
        }

        static bool IsSameIp(PacketBuffer packet, int offsetA, int offsetB)
        {
            return packet.Buffer[offsetA] == packet.Buffer[offsetB]
                && packet.Buffer[offsetA + 1] == packet.Buffer[offsetB + 1]
                && packet.Buffer[offsetA + 2] == packet.Buffer[offsetB + 2]
                && packet.Buffer[offsetA + 3] == packet.Buffer[offsetB + 3];
        }

        static class RawSender
        {
            [DllImport("libc.so.6", EntryPoint = "socket")]
            static extern int socket(int domain, int type, int protocol);

            [DllImport("libc.so.6", EntryPoint = "setsockopt")]
            static extern int setsockopt(int sockfd, int level, int optname, ref int optval, uint optlen);

            [DllImport("libc.so.6", EntryPoint = "sendto")]
            static extern int sendto(int sockfd, byte[] buf, int len, int flags,
                ref SockAddrIn addr, int addrlen);

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

            public static void Init()
            {
                _fd = socket(2, 3, 255);
                if (_fd < 0) throw new Exception("创建 Raw Socket 失败，需要 root 权限");
                int one = 1;
                setsockopt(_fd, 0, 3, ref one, 4);
                Console.WriteLine("Raw Socket 已初始化");
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
                    Console.WriteLine($"[RAW] 发送失败 len={packet.Length}");
            }
        }

        class Program
        {
            public static int ListenPort = 12345;

            public static readonly Channel<PacketBuffer> RX_channel =
                Channel.CreateBounded<PacketBuffer>(new BoundedChannelOptions(8192)
                {
                    SingleReader = true,
                    SingleWriter = true,
                    FullMode = BoundedChannelFullMode.Wait
                });

            public static readonly Channel<PacketBuffer> TX_channel =
                Channel.CreateBounded<PacketBuffer>(new BoundedChannelOptions(8192)
                {
                    SingleReader = true,
                    SingleWriter = true,
                    FullMode = BoundedChannelFullMode.Wait
                });

            static string TunnelIP = "172.30.98.75";
            static int[] ports = { 19191 };

            static async Task Main(string[] args)
            {
                const string configPath = "config.json";
                var config = ConfigManager.LoadOrCreate<VirtualIPConfig>(configPath);
                TunnelIP = config.VirtualIp;
                ListenPort = config.ListenPort;
                ports = config.Ports;
                if (string.IsNullOrWhiteSpace(TunnelIP))
                    throw new InvalidOperationException("config.json: VirtualIp 不能为空");
                if (ListenPort <= 0 || ListenPort > 65535)
                    throw new InvalidOperationException("config.json: ListenPort 必须是 1-65535");
                if (ports.Length == 0 || ports.Any(port => port <= 0 || port > 65535))
                    throw new InvalidOperationException("config.json: Ports 必须是 1-65535 的端口列表");
                if (string.IsNullOrWhiteSpace(config.ClientID))
                    throw new InvalidOperationException("config.json: ClientID 不能为空");
                if (string.IsNullOrWhiteSpace(config.Secret))
                {
                    config.Secret = GenerateSecret();
                    ConfigManager.Save(configPath, config);
                    Console.WriteLine("已生成 Secret 并写入 config.json");
                }
                Console.WriteLine($"配置: TunnelIP={TunnelIP}, ListenPort={ListenPort}, Ports={string.Join(",", ports)}, ClientID={config.ClientID}");

                var cert = GenerateSelfSignedCertificate();
                var listener = new TcpListener(IPAddress.Any, ListenPort);
                listener.Start();
                Console.WriteLine($"服务端监听端口 {ListenPort}");

                using var cts = new CancellationTokenSource();

                Console.CancelKeyPress += (_, e) =>
                {
                    e.Cancel = true;
                    IptablesManager.Remove(ports);
                    cts.Cancel();
                };
                AppDomain.CurrentDomain.ProcessExit += (_, _) =>
                {
                    IptablesManager.Remove(ports);
                };

                var (controlTcp, controlSsl, txTcp, txSsl, rxTcp, rxSsl) =
                    await AcceptAuthenticatedClientAsync(listener, cert, config, cts.Token);

                var json = JsonConvert.SerializeObject(new { TunnelIP, Ports = ports });
                await SendAsync(controlSsl, Encoding.UTF8.GetBytes(json), cts.Token);
                Console.WriteLine($"已下发 TunnelIP: {TunnelIP}, Ports: {string.Join(",", ports)}");

                RawSender.Init();
                IptablesManager.Add(ports);
                NFQueue.Start(100, TunnelIP, TX_channel, cts.Token);

                _ = Task.Run(() => RawInjectLoop(cts.Token), cts.Token);

                Console.WriteLine("开始转发...");

                await Task.WhenAll(
                    ReceiveLoopAsync(txSsl, cts.Token),
                    SendLoopAsync(rxSsl, cts.Token)
                );

                controlSsl.Dispose(); controlTcp.Dispose();
                txSsl.Dispose(); txTcp.Dispose();
                rxSsl.Dispose(); rxTcp.Dispose();
                listener.Stop();
            }

            static async Task<(TcpClient ControlTcp, SslStream ControlSsl, TcpClient TxTcp, SslStream TxSsl, TcpClient RxTcp, SslStream RxSsl)>
                AcceptAuthenticatedClientAsync(TcpListener listener, X509Certificate2 cert, VirtualIPConfig config, CancellationToken ct)
            {
                while (!ct.IsCancellationRequested)
                {
                    Console.WriteLine("等待控制连接...");
                    var controlTcp = await listener.AcceptTcpClientAsync(ct);
                    controlTcp.NoDelay = true;
                    var controlSsl = new SslStream(controlTcp.GetStream(), false);
                    await controlSsl.AuthenticateAsServerAsync(cert, false, false);
                    Console.WriteLine($"控制连接来自 {controlTcp.Client.RemoteEndPoint}");

                    Console.WriteLine("等待TX数据连接...");
                    var txTcp = await listener.AcceptTcpClientAsync(ct);
                    txTcp.NoDelay = true;
                    var txSsl = new SslStream(txTcp.GetStream(), false);
                    await txSsl.AuthenticateAsServerAsync(cert, false, false);
                    Console.WriteLine($"TX数据连接来自 {txTcp.Client.RemoteEndPoint}");

                    Console.WriteLine("等待RX数据连接...");
                    var rxTcp = await listener.AcceptTcpClientAsync(ct);
                    rxTcp.NoDelay = true;
                    var rxSsl = new SslStream(rxTcp.GetStream(), false);
                    await rxSsl.AuthenticateAsServerAsync(cert, false, false);
                    Console.WriteLine($"RX数据连接来自 {rxTcp.Client.RemoteEndPoint}");

                    bool authenticated = false;
                    try
                    {
                        Console.WriteLine("[AUTH] 等待客户端认证...");
                        authenticated = await AuthenticateClientAsync(controlSsl, config, ct);
                        await SendAsync(controlSsl, Encoding.UTF8.GetBytes(authenticated ? "Success" : "Failed"), ct);
                        Console.WriteLine($"[AUTH] 已返回认证结果: {(authenticated ? "Success" : "Failed")}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"认证异常: {ex.Message}");
                    }

                    if (authenticated)
                    {
                        Console.WriteLine($"认证成功: {config.ClientID}");
                        return (controlTcp, controlSsl, txTcp, txSsl, rxTcp, rxSsl);
                    }

                    Console.WriteLine("认证失败，等待下一个客户端");
                    controlSsl.Dispose(); controlTcp.Dispose();
                    txSsl.Dispose(); txTcp.Dispose();
                    rxSsl.Dispose(); rxTcp.Dispose();
                }

                throw new OperationCanceledException(ct);
            }

            sealed class AuthenticationRequest
            {
                public string ClientID { get; set; } = "";
                public long Timestamp { get; set; }
                public string Sign { get; set; } = "";
            }

            static async Task<bool> AuthenticateClientAsync(SslStream controlSsl, VirtualIPConfig config, CancellationToken ct)
            {
                using var data = await ReceiveAsync(controlSsl, ct);
                string json = Encoding.UTF8.GetString(data.Buffer, 0, data.Length);
                var request = JsonConvert.DeserializeObject<AuthenticationRequest>(json);
                if (request == null)
                {
                    Console.WriteLine("[AUTH] 失败: 请求格式无效");
                    return false;
                }

                Console.WriteLine($"[AUTH] 收到认证 ClientID={request.ClientID}, Timestamp={request.Timestamp}");

                if (!string.Equals(request.ClientID, config.ClientID, StringComparison.Ordinal))
                {
                    Console.WriteLine($"[AUTH] 失败: ClientID 不匹配，期望={config.ClientID}");
                    return false;
                }

                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (Math.Abs(now - request.Timestamp) > 300)
                {
                    Console.WriteLine($"[AUTH] 失败: Timestamp 超时，now={now}");
                    return false;
                }

                string expectedSign = ComputeSign(config.Secret, request.ClientID, request.Timestamp);
                if (!FixedTimeHexEquals(expectedSign, request.Sign))
                {
                    Console.WriteLine("[AUTH] 失败: Sign 不匹配");
                    return false;
                }

                return true;
            }

            static string ComputeSign(string secret, string clientId, long timestamp)
            {
                byte[] key = Encoding.UTF8.GetBytes(secret);
                byte[] msg = Encoding.UTF8.GetBytes($"{clientId}:{timestamp}");
                using var hmac = new HMACSHA256(key);
                return Convert.ToHexString(hmac.ComputeHash(msg));
            }

            static string GenerateSecret()
            {
                return Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
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

            static async Task RawInjectLoop(CancellationToken ct)
            {
                while (!ct.IsCancellationRequested)
                {
                    var packet = await RX_channel.Reader.ReadAsync(ct);
                    using (packet)
                    {
                        RawSender.Send(packet);
                    }
                }
            }

            static async Task ReceiveLoopAsync(SslStream dataSsl, CancellationToken ct)
            {
                try
                {
                    while (!ct.IsCancellationRequested)
                    {
                        var data = await ReceiveAsync(dataSsl, ct);
                        try
                        {
                            await RX_channel.Writer.WriteAsync(data, ct);
                        }
                        catch
                        {
                            data.Dispose();
                            throw;
                        }
                    }
                }
                catch (OperationCanceledException) { }
                catch (Exception ex) { Console.WriteLine($"数据连接断开(收): {ex.Message}"); }
            }

            static async Task SendLoopAsync(SslStream dataSsl, CancellationToken ct)
            {
                try
                {
                    while (!ct.IsCancellationRequested)
                    {
                        var data = await TX_channel.Reader.ReadAsync(ct);
                        using (data)
                        {
                            await SendAsync(dataSsl, data.ReadOnlyMemory, ct);
                        }
                    }
                }
                catch (OperationCanceledException) { }
                catch (Exception ex) { Console.WriteLine($"数据连接断开(发): {ex.Message}"); }
            }

            static async Task SendAsync(SslStream ssl, ReadOnlyMemory<byte> data, CancellationToken ct)
            {
                var buffer = ArrayPool<byte>.Shared.Rent(4 + data.Length);
                try
                {
                    BinaryPrimitives.WriteInt32BigEndian(buffer, data.Length);
                    data.CopyTo(buffer.AsMemory(4));
                    await ssl.WriteAsync(buffer.AsMemory(0, 4 + data.Length), ct);
                }
                finally { ArrayPool<byte>.Shared.Return(buffer); }
            }

            static async Task<PacketBuffer> ReceiveAsync(SslStream ssl, CancellationToken ct)
            {
                var lenBuf = ArrayPool<byte>.Shared.Rent(4);
                int totalLen;
                try
                {
                    await ssl.ReadExactlyAsync(lenBuf.AsMemory(0, 4), ct);
                    totalLen = BinaryPrimitives.ReadInt32BigEndian(lenBuf.AsSpan(0, 4));
                }
                finally { ArrayPool<byte>.Shared.Return(lenBuf); }

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

            static X509Certificate2 GenerateSelfSignedCertificate()
            {
                using var rsa = RSA.Create(2048);
                var req = new CertificateRequest("cn=VirtualIPServer", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
                return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null);
            }
        }
    }
}
