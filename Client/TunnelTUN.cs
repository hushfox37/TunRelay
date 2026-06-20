using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;


namespace TunRelayClient
{
    public static class Protocol
    {
        public const byte HOPOPT = 0x00;          // IPv6 Hop-by-Hop
        public const byte ICMP = 0x01;
        public const byte IGMP = 0x02;
        public const byte GGP = 0x03;
        public const byte TCP = 0x06;
        public const byte EGP = 0x08;
        public const byte PUP = 0x0C;
        public const byte UDP = 0x11;
        public const byte HMP = 0x14;
        public const byte XNS_IDP = 0x16;
        public const byte RDP = 0x1B;
        public const byte IPv6 = 0x29;
        public const byte IPv6_Route = 0x2B;
        public const byte IPv6_Frag = 0x2C;
        public const byte GRE = 0x2F;
        public const byte ESP = 0x32;
        public const byte AH = 0x33;
        public const byte ICMPv6 = 0x3A;
        public const byte NoNextHeader = 0x3B;
        public const byte IPv6_Opts = 0x3C;
        public const byte EIGRP = 0x58;
        public const byte OSPF = 0x59;
        public const byte L2TP = 0x73;
        public const byte SCTP = 0x84;
        public const byte UDPLite = 0x88;
        public const byte MobilityHeader = 0x87;
        public const byte EtherIP = 0x61;
        public const byte PIM = 0x67;
    }
    class TUN
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr WintunCreateAdapterDelegate(
            [MarshalAs(UnmanagedType.LPWStr)] string name,
            [MarshalAs(UnmanagedType.LPWStr)] string tunnelType,
            in Guid requestedGuid);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr WintunStartSessionDelegate(IntPtr adapter, uint capacity);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr WintunReceivePacketDelegate(IntPtr session, out uint packetSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr WintunAllocateSendPacketDelegate(IntPtr session, uint packetSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void WintunSendPacketDelegate(IntPtr session, IntPtr packet);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void WintunReleaseReceivePacketDelegate(IntPtr session, IntPtr packet);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void WintunEndSessionDelegate(IntPtr session);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void WintunCloseAdapterDelegate(IntPtr adapter);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void WintunGetAdapterLuidDelegate(IntPtr adapter, out ulong luid);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr WintunGetReadWaitEventDelegate(IntPtr session);

        [StructLayout(LayoutKind.Sequential)]
        struct NET_LUID
        {
            public ulong Value;
        }

        [StructLayout(LayoutKind.Explicit)]
        struct SOCKADDR_INET
        {
            [FieldOffset(0)] public short si_family;
            // IPv4
            [FieldOffset(2)] public ushort sin_port;
            [FieldOffset(4)] public uint sin_addr;
            // IPv6
            [FieldOffset(2)] public ushort sin6_port;
            [FieldOffset(4)] public uint sin6_flowinfo;
            [FieldOffset(8)] public ulong sin6_addr0;
            [FieldOffset(16)] public ulong sin6_addr1;
            [FieldOffset(24)] public uint sin6_scope_id;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_UNICASTIPADDRESS_ROW
        {
            public SOCKADDR_INET Address;
            public NET_LUID InterfaceLuid;
            public uint InterfaceIndex;
            public uint PrefixOrigin;
            public uint SuffixOrigin;
            public uint ValidLifetime;
            public uint PreferredLifetime;
            public byte OnLinkPrefixLength;
            public byte SkipAsSource;
            public uint DadState;
            public uint ScopeId;
            public long CreationTimeStamp;
        }

        [DllImport("iphlpapi.dll", EntryPoint = "CreateUnicastIpAddressEntry")]
        static extern uint AddUnicastIpAddressEntry(ref MIB_UNICASTIPADDRESS_ROW row);

        [DllImport("iphlpapi.dll", EntryPoint = "InitializeUnicastIpAddressEntry")]
        static extern void InitializeUnicastIpAddressEntry(ref MIB_UNICASTIPADDRESS_ROW row);

        [DllImport("iphlpapi.dll", EntryPoint = "ConvertInterfaceLuidToIndex")]
        static extern uint ConvertInterfaceLuidToIndex(ref NET_LUID interfaceLuid, out uint interfaceIndex);

        private static readonly object PeerRouteLock = new();
        private static readonly HashSet<string> PeerRoutes = new();
        private static bool EnableDynamicPeerRoutes = true;

        public readonly Channel<PacketBuffer> RX_channel;
        public readonly Channel<PacketBuffer> TX_channel;
        private readonly HashSet<int> ServicePorts;
        public string IP;
        private static ILogger logger;
        public TUN(string ip, IEnumerable<int> servicePorts, Channel<PacketBuffer> rx_channel, Channel<PacketBuffer> tx_channel)
        {
            this.IP = ip;
            this.ServicePorts = servicePorts.ToHashSet();
            this.RX_channel = rx_channel;
            this.TX_channel = tx_channel;

            var services = new ServiceCollection();

            services.AddLogging(builder =>
            {
                builder.AddSimpleConsole(options =>
                {
                    options.SingleLine = true;
                    options.TimestampFormat = "yyyy/MM/dd HH:mm:ss ";
                });
            });

            using var provider = services.BuildServiceProvider();

            logger = provider
                .GetRequiredService<ILoggerFactory>()
                .CreateLogger("");

        }
        public async Task StartAsync(string IP, CancellationToken ct = default)
        {
            this.IP = IP;
            //加载wintun.dll,获取函数指针
            IntPtr _lib = NativeLibrary.Load("wintun.dll");
            var createAdapter = Marshal.GetDelegateForFunctionPointer<WintunCreateAdapterDelegate>(
                NativeLibrary.GetExport(_lib, "WintunCreateAdapter"));
            var startSession = Marshal.GetDelegateForFunctionPointer<WintunStartSessionDelegate>(
                NativeLibrary.GetExport(_lib, "WintunStartSession"));
            var getReadWaitEvent = Marshal.GetDelegateForFunctionPointer<WintunGetReadWaitEventDelegate>(
                NativeLibrary.GetExport(_lib, "WintunGetReadWaitEvent"));
            var adapter = createAdapter("Tunnel", "TunRelay", Guid.NewGuid());
            // 检查适配器是否创建成功
            if (adapter == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                logger?.LogError($"CreateAdapter 失败，错误码: {err}");
                return;
            }

            var getAdapterLuid = Marshal.GetDelegateForFunctionPointer<WintunGetAdapterLuidDelegate>(
                NativeLibrary.GetExport(_lib, "WintunGetAdapterLUID"));

            //配置IPv4
            getAdapterLuid(adapter, out ulong luid);
            SetIPv4Address(luid, IP, 32);
            var netLuid = new NET_LUID { Value = luid };
            uint interfaceIndex = 0;
            uint indexResult = ConvertInterfaceLuidToIndex(ref netLuid, out interfaceIndex);
            if (indexResult != 0)
                logger?.LogWarning($"ConvertInterfaceLuidToIndex failed: {indexResult}");
            else
                logger?.LogInformation($"WinTun interface index: {interfaceIndex}");

            //开始会话
            var receivePacket = Marshal.GetDelegateForFunctionPointer<WintunReceivePacketDelegate>(
                NativeLibrary.GetExport(_lib, "WintunReceivePacket"));

            var releaseReceivePacket = Marshal.GetDelegateForFunctionPointer<WintunReleaseReceivePacketDelegate>(
                NativeLibrary.GetExport(_lib, "WintunReleaseReceivePacket"));

            var session = startSession(adapter, 0x400000);
            var readWaitEvent = getReadWaitEvent(session);

            var allocateSendPacket =
                Marshal.GetDelegateForFunctionPointer<WintunAllocateSendPacketDelegate>(
                    NativeLibrary.GetExport(_lib, "WintunAllocateSendPacket"));

            var sendPacket =
                Marshal.GetDelegateForFunctionPointer<WintunSendPacketDelegate>(
                    NativeLibrary.GetExport(_lib, "WintunSendPacket"));

            _ = Task.Run(async () => await ReadTUNAsync(RX_channel, IP, ServicePorts, readWaitEvent, receivePacket, releaseReceivePacket, session, readWaitEvent, ct));
            _ = Task.Run(async () => await ChannelToTunAsync(TX_channel, IP, interfaceIndex, allocateSendPacket, sendPacket, session, ct));
        }

        public static void SetIPv4Address(ulong luid, string ip, byte prefixLength)
        {
            var row = new MIB_UNICASTIPADDRESS_ROW();
            InitializeUnicastIpAddressEntry(ref row);

            row.InterfaceLuid = new NET_LUID { Value = luid };
            row.Address.si_family = 2; // AF_INET
            row.Address.sin_addr = BitConverter.ToUInt32(
                System.Net.IPAddress.Parse(ip).GetAddressBytes(), 0);
            row.OnLinkPrefixLength = prefixLength;
            row.ValidLifetime = 0xFFFFFFFF;
            row.PreferredLifetime = 0xFFFFFFFF;

            uint result = AddUnicastIpAddressEntry(ref row);
            if (result != 0)
                logger?.LogError($"设置IP失败,错误码: {result}");
            else
                logger?.LogInformation($"IP设置成功: {ip}/{prefixLength}");
        }

        private static async IAsyncEnumerable<PacketBuffer> ReadAsync(
            IntPtr eventHandle,
            WintunReceivePacketDelegate receivePacket,
            WintunReleaseReceivePacketDelegate releaseReceivePacket,
            IntPtr session,
            [EnumeratorCancellation] CancellationToken ct = default)
        {
            var waitHandle = new AutoResetEvent(false);
            waitHandle.SafeWaitHandle = new SafeWaitHandle(eventHandle, false);

            // 信号 Channel，容量1即可，多次触发合并成一次唤醒
            var signal = Channel.CreateBounded<bool>(new BoundedChannelOptions(1)
            {
                FullMode = BoundedChannelFullMode.DropWrite  // buffer 满了就丢，反正只是触发信号
            });

            // 注册到 ThreadPool wait 队列，不占用线程
            var registration = ThreadPool.RegisterWaitForSingleObject(
                waitHandle,
                (_, _) => signal.Writer.TryWrite(true),
                null,
                Timeout.Infinite,
                executeOnlyOnce: false
            );

            try
            {
                while (!ct.IsCancellationRequested)
                {
                    // 排空 ring buffer
                    while (true)
                    {
                        var pkt = receivePacket(session, out uint size);
                        if (pkt == IntPtr.Zero) break;

                        var data = PacketBuffer.Rent((int)size);
                        Marshal.Copy(pkt, data.Buffer, 0, (int)size);
                        releaseReceivePacket(session, pkt);
                        yield return data;
                    }

                    // 等信号，不阻塞线程
                    await signal.Reader.ReadAsync(ct);
                }
            }
            finally
            {
                registration.Unregister(null); // 取消注册，避免泄漏
            }
        }

        private static async Task ReadTUNAsync(Channel<PacketBuffer> channel,
            string tunnelIp,
            HashSet<int> servicePorts,
            IntPtr eventHandle,
            WintunReceivePacketDelegate receivePacket,
            WintunReleaseReceivePacketDelegate releaseReceivePacket,
            IntPtr session,
            nint readWaitEvent,
            CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                await foreach (var packet in ReadAsync(
                readWaitEvent,
                receivePacket,
                releaseReceivePacket,
                session,
                ct))
                {
                    if (packet.Length < 20
                        || packet.Buffer[0] >> 4 != 4
                        || ((packet.Buffer[9] != Protocol.TCP) && (packet.Buffer[9] != Protocol.UDP)))
                    {
                        packet.Dispose();
                        continue;
                    }

                    byte d1 = packet.Buffer[16];
                    byte d4 = packet.Buffer[19];
                    if (d1 >= 224 && d1 <= 239 || d4 == 255)
                    {
                        packet.Dispose();
                        continue;
                    }

                    try
                    {
                        await channel.Writer.WriteAsync(packet, ct);
                    }
                    catch
                    {
                        packet.Dispose();
                        throw;
                    }
                }
            }
        }


        private static async Task WriteToTunAsync(
            WintunAllocateSendPacketDelegate allocateSendPacket,
            WintunSendPacketDelegate sendPacket,
            IntPtr session,
            string tunnelIp,
            uint interfaceIndex,
            PacketBuffer data,
            CancellationToken ct = default)
        {
            if (EnableDynamicPeerRoutes)
            {
                EnsurePeerRoute(data, tunnelIp, interfaceIndex);
            }

            int spin = 0;
            while (!ct.IsCancellationRequested)
            {
                var ptr = allocateSendPacket(session, (uint)data.Length);
                if (ptr != IntPtr.Zero)
                {
                    Marshal.Copy(data.Buffer, 0, ptr, data.Length);
                    sendPacket(session, ptr);
                    return;
                }
                if (spin++ < 10) Thread.SpinWait(20);
                else await Task.Yield();
            }
        }

        private static void EnsurePeerRoute(PacketBuffer packet, string tunnelIp, uint interfaceIndex)
        {
            if (interfaceIndex == 0) return;
            if (packet.Length < 20 || packet.Buffer[0] >> 4 != 4) return;

            var src = $"{packet.Buffer[12]}.{packet.Buffer[13]}.{packet.Buffer[14]}.{packet.Buffer[15]}";
            var dst = $"{packet.Buffer[16]}.{packet.Buffer[17]}.{packet.Buffer[18]}.{packet.Buffer[19]}";
            if (dst != tunnelIp || src == tunnelIp || src == dst) return;

            lock (PeerRouteLock)
            {
                if (!PeerRoutes.Add(src)) return;
            }

            var psi = new ProcessStartInfo("route", $"ADD {src} MASK 255.255.255.255 0.0.0.0 METRIC 1 IF {interfaceIndex}")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            try
            {
                using var process = Process.Start(psi);
                if (process == null)
                {
                    logger?.LogDebug($"[ROUTE] failed to start route.exe for {src}/32");
                    return;
                }

                process.WaitForExit(3000);
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                if (process.ExitCode == 0)
                    logger?.LogInformation($"[ROUTE] {src}/32 -> if {interfaceIndex}");
                else
                    logger?.LogInformation($"[ROUTE] failed {src}/32 -> if {interfaceIndex} exit={process.ExitCode} {output}{error}");
            }
            catch (Exception ex)
            {
                logger?.LogWarning($"[ROUTE] exception {src}/32 -> if {interfaceIndex}: {ex.Message}");
            }
        }

        private static async Task ChannelToTunAsync(
            Channel<PacketBuffer> channel,
            string tunnelIp,
            uint interfaceIndex,
            WintunAllocateSendPacketDelegate allocateSendPacket,
            WintunSendPacketDelegate sendPacket,
            IntPtr session,
            CancellationToken ct = default
        )
        {
            while (!ct.IsCancellationRequested)
            {
                var data = await channel.Reader.ReadAsync(ct);
                using (data)
                {
                    await WriteToTunAsync(allocateSendPacket, sendPacket, session, tunnelIp, interfaceIndex, data, ct);
                }
            }
        }
    }
}
