using System.Collections.Generic;
using System.Buffers.Binary;
using System.Diagnostics;
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

    internal static class PacketFilter
    {
        public static bool ShouldForward(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length < 20) return false;
            if (buffer[0] >> 4 != 4) return false;
            if (buffer[9] != Protocol.TCP && buffer[9] != Protocol.UDP) return false;

            byte d1 = buffer[16], d4 = buffer[19];
            if (d1 is >= 224 and <= 239 || d4 == 255) return false;

            return true;
        }
    }

    internal sealed class PeerRouteTracker
    {
        private readonly object _lock = new();
        private readonly HashSet<uint> _peers = new();
        private uint _tunnelIp;

        public void SetTunnelIp(uint tunnelIp) => _tunnelIp = tunnelIp;

        public bool TryRegister(ReadOnlySpan<byte> buffer, out string srcIp)
        {
            srcIp = "";
            if (buffer.Length < 20 || buffer[0] >> 4 != 4) return false;

            uint src = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(12));
            uint dst = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(16));
            if (dst != _tunnelIp || src == _tunnelIp || src == dst) return false;

            lock (_lock)
            {
                if (!_peers.Add(src)) return false;
            }

            srcIp = FormatIp(src);
            return true;
        }

        public static uint ParseIp(string ip)
        {
            Span<byte> bytes = stackalloc byte[4];
            if (!System.Net.IPAddress.TryParse(ip, out var address)
                || !address.TryWriteBytes(bytes, out int written)
                || written != 4)
                throw new InvalidOperationException($"Invalid IPv4 address: {ip}");

            return BinaryPrimitives.ReadUInt32BigEndian(bytes);
        }

        public static string FormatIp(uint ip)
        {
            return $"{(ip >> 24) & 0xff}.{(ip >> 16) & 0xff}.{(ip >> 8) & 0xff}.{ip & 0xff}";
        }
    }

    public interface ITunDriver : IAsyncDisposable
    {
        Task InitAsync(string ip, CancellationToken ct = default);
        Task ReadAsync(Channel<PacketBuffer> channel, CancellationToken ct);
        Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default);
    }

    public static class TunDriverFactory
    {
        public static ITunDriver Create()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return new WintunDriver();
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return new LinuxTunDriver();

            throw new PlatformNotSupportedException("Only Windows Wintun and Linux TUN");
        }
    }

    class TUN
    {
        private readonly ITunDriver Driver;
        public readonly Channel<PacketBuffer> RX_channel;

        public TUN(ITunDriver driver, Channel<PacketBuffer> rx_channel)
        {
            Driver = driver;
            RX_channel = rx_channel;
        }

        public async Task StartAsync(string ip, CancellationToken ct = default)
        {
            await Driver.InitAsync(ip, ct);
            _ = Task.Run(() => Driver.ReadAsync(RX_channel, ct), ct);
        }

        /// <summary>
        /// 出口: 直接把单个 IP 包写入 TUN 设备。由接收端 batch 解码循环逐包调用。
        /// </summary>
        public Task WriteAsync(ReadOnlyMemory<byte> packet, CancellationToken ct = default)
            => Driver.WriteAsync(packet, ct);
    }

    public class WintunDriver : ITunDriver
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

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void WintunGetAdapterLUIDDelegate(IntPtr adapter, out ulong LUID);

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

        private IntPtr _lib;
        private IntPtr _adapter;
        private IntPtr _session;
        private IntPtr _readWaitEvent;
        private WintunReceivePacketDelegate _receivePacket = null!;
        private WintunReleaseReceivePacketDelegate _releaseReceivePacket = null!;
        private WintunAllocateSendPacketDelegate _allocateSendPacket = null!;
        private WintunSendPacketDelegate _sendPacket = null!;
        private WintunEndSessionDelegate _endSession = null!;
        private WintunCloseAdapterDelegate _closeAdapter = null!;

        private readonly PeerRouteTracker _peerRoutes = new();
        private static ILogger? logger => Program.logger;

        private readonly Channel<string> _routeQueue = Channel.CreateBounded<string>(
            new BoundedChannelOptions(256)
            {
                FullMode = BoundedChannelFullMode.DropWrite,
                SingleReader = true
            });
        private Task? _routeWorker;

        public uint interfaceIndex { get; private set; }
        public string tunnelIp { get; private set; } = "";

        public Task InitAsync(string ip, CancellationToken ct = default)
        {
            if (_lib != IntPtr.Zero)
                throw new InvalidOperationException("Already initialized");

            _lib = NativeLibrary.Load("wintun.dll");

            var createAdapter = Marshal.GetDelegateForFunctionPointer<WintunCreateAdapterDelegate>(
                NativeLibrary.GetExport(_lib, "WintunCreateAdapter"));
            var startSession = Marshal.GetDelegateForFunctionPointer<WintunStartSessionDelegate>(
                NativeLibrary.GetExport(_lib, "WintunStartSession"));
            var getReadWaitEvent = Marshal.GetDelegateForFunctionPointer<WintunGetReadWaitEventDelegate>(
                NativeLibrary.GetExport(_lib, "WintunGetReadWaitEvent"));
            var getAdapterLUID = Marshal.GetDelegateForFunctionPointer<WintunGetAdapterLUIDDelegate>(
                NativeLibrary.GetExport(_lib, "WintunGetAdapterLUID"));

            _endSession = Marshal.GetDelegateForFunctionPointer<WintunEndSessionDelegate>(
                NativeLibrary.GetExport(_lib, "WintunEndSession"));
            _closeAdapter = Marshal.GetDelegateForFunctionPointer<WintunCloseAdapterDelegate>(
                NativeLibrary.GetExport(_lib, "WintunCloseAdapter"));
            _receivePacket = Marshal.GetDelegateForFunctionPointer<WintunReceivePacketDelegate>(
                NativeLibrary.GetExport(_lib, "WintunReceivePacket"));
            _releaseReceivePacket = Marshal.GetDelegateForFunctionPointer<WintunReleaseReceivePacketDelegate>(
                NativeLibrary.GetExport(_lib, "WintunReleaseReceivePacket"));
            _allocateSendPacket = Marshal.GetDelegateForFunctionPointer<WintunAllocateSendPacketDelegate>(
                NativeLibrary.GetExport(_lib, "WintunAllocateSendPacket"));
            _sendPacket = Marshal.GetDelegateForFunctionPointer<WintunSendPacketDelegate>(
                NativeLibrary.GetExport(_lib, "WintunSendPacket"));

            _adapter = createAdapter("Tunnel", "TunRelay", Guid.NewGuid());
            if (_adapter == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"CreateAdapter failed, error code: {err}");
            }

            getAdapterLUID(_adapter, out ulong LUID);
            SetIPv4Address(LUID, ip, 32);

            var netLUID = new NET_LUID { Value = LUID };
            uint idx = 0;
            uint indexResult = ConvertInterfaceLuidToIndex(ref netLUID, out idx);
            if (indexResult != 0)
                logger?.LogWarning($"ConvertInterfaceLuidToIndex failed: {indexResult}");
            else
                logger?.LogInformation($"WinTun interface index: {idx}");

            _session = startSession(_adapter, 0x400000);
            _readWaitEvent = getReadWaitEvent(_session);

            tunnelIp = ip;
            interfaceIndex = idx;
            _peerRoutes.SetTunnelIp(PeerRouteTracker.ParseIp(ip));

            _routeWorker = Task.Run(() => RouteWorkerAsync(ct), ct);

            return Task.CompletedTask;
        }

        private static void SetIPv4Address(ulong LUID, string ip, byte prefixLength)
        {
            var row = new MIB_UNICASTIPADDRESS_ROW();
            InitializeUnicastIpAddressEntry(ref row);

            row.InterfaceLuid = new NET_LUID { Value = LUID };
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

        public async Task ReadAsync(Channel<PacketBuffer> channel, CancellationToken ct)
        {
            await foreach (var packet in ReadPacketsAsync(ct))
            {
                if (!PacketFilter.ShouldForward(packet.ReadOnlyMemory.Span))
                {
                    packet.Dispose();
                    continue;
                }

                // 队列满则丢弃新包(不阻塞读取线程),并计数
                if (!channel.Writer.TryWrite(packet))
                {
                    packet.Dispose();
                    TunnelStats.IncrementChannelDrops();
                }
            }
        }

        private async IAsyncEnumerable<PacketBuffer> ReadPacketsAsync(
            [EnumeratorCancellation] CancellationToken ct = default)
        {
            var waitHandle = new AutoResetEvent(false);
            waitHandle.SafeWaitHandle = new SafeWaitHandle(_readWaitEvent, false);

            var signal = Channel.CreateBounded<bool>(new BoundedChannelOptions(1)
            {
                FullMode = BoundedChannelFullMode.DropWrite
            });

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
                    while (true)
                    {
                        var pkt = _receivePacket(_session, out uint size);
                        if (pkt == IntPtr.Zero) break;

                        var data = PacketBuffer.Rent((int)size);
                        Marshal.Copy(pkt, data.Buffer, 0, (int)size);
                        _releaseReceivePacket(_session, pkt);
                        yield return data;
                    }

                    await signal.Reader.ReadAsync(ct);
                }
            }
            finally
            {
                registration.Unregister(null);
            }
        }

        public async Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
        {
            EnsurePeerRoute(data.Span);

            int len = data.Length;
            int spin = 0;
            while (!ct.IsCancellationRequested)
            {
                var ptr = _allocateSendPacket(_session, (uint)len);
                if (ptr != IntPtr.Zero)
                {
                    CopyToNative(data.Span, ptr);
                    _sendPacket(_session, ptr);
                    return;
                }

                if (spin++ < 10) Thread.SpinWait(20);
                else await Task.Yield();
            }
        }

        private static unsafe void CopyToNative(ReadOnlySpan<byte> src, IntPtr dst)
        {
            var dest = new Span<byte>((void*)dst, src.Length);
            src.CopyTo(dest);
        }

        // 出口热路径只做注册判断 + 入队,真正的 route.exe 调用在后台 worker 执行,避免阻塞写包。
        private void EnsurePeerRoute(ReadOnlySpan<byte> packet)
        {
            if (interfaceIndex == 0) return;
            if (!_peerRoutes.TryRegister(packet, out var src)) return;

            if (_routeQueue.Writer.TryWrite(src))
                TunnelStats.IncrementRouteUpdatesQueued();
        }

        private async Task RouteWorkerAsync(CancellationToken ct)
        {
            try
            {
                await foreach (var src in _routeQueue.Reader.ReadAllAsync(ct))
                    RunRouteCommand(src);
            }
            catch (OperationCanceledException) { }
        }

        private void RunRouteCommand(string src)
        {
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
                    TunnelStats.IncrementRouteUpdateFailures();
                    return;
                }

                process.WaitForExit(3000);
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                if (process.ExitCode == 0)
                    logger?.LogInformation($"[ROUTE] {src}/32 -> if {interfaceIndex}");
                else
                {
                    logger?.LogInformation($"[ROUTE] failed {src}/32 -> if {interfaceIndex} exit={process.ExitCode} {output}{error}");
                    TunnelStats.IncrementRouteUpdateFailures();
                }
            }
            catch (Exception ex)
            {
                logger?.LogWarning($"[ROUTE] exception {src}/32 -> if {interfaceIndex}: {ex.Message}");
                TunnelStats.IncrementRouteUpdateFailures();
            }
        }

        public ValueTask DisposeAsync()
        {
            if (_session != IntPtr.Zero)
            {
                _endSession?.Invoke(_session);
                _session = IntPtr.Zero;
            }

            if (_adapter != IntPtr.Zero)
            {
                _closeAdapter?.Invoke(_adapter);
                _adapter = IntPtr.Zero;
            }

            if (_lib != IntPtr.Zero)
            {
                NativeLibrary.Free(_lib);
                _lib = IntPtr.Zero;
            }

            return ValueTask.CompletedTask;
        }
    }
    public class LinuxTunDriver : ITunDriver
    {
        static class Libc
        {
            const string Lib = "libc";

            [DllImport(Lib, SetLastError = true)]
            public static extern int open(string path, int flags);

            [DllImport(Lib, SetLastError = true)]
            public static extern int close(int fd);

            [DllImport(Lib, SetLastError = true)]
            public static extern int read(int fd, byte[] buf, int count);

            [DllImport(Lib, SetLastError = true)]
            public static extern int write(int fd, byte[] buf, int count);

            [DllImport(Lib, SetLastError = true)]
            public static extern int write(int fd, IntPtr buf, int count);

            [DllImport(Lib, SetLastError = true)]
            public static extern int fcntl(int fd, int cmd, int arg);

            [DllImport(Lib, SetLastError = true)]
            public static extern int socket(int domain, int type, int protocol);

            [DllImport(Lib, SetLastError = true)]
            public static extern int eventfd(uint initval, int flags);

            [DllImport(Lib, SetLastError = true)]
            public static extern int epoll_create1(int flags);

            [DllImport(Lib, SetLastError = true)]
            public static extern int epoll_ctl(int epfd, int op, int fd, ref epoll_event ev);

            [DllImport(Lib, SetLastError = true)]
            public static extern int epoll_wait(int epfd, [Out] epoll_event[] events, int maxevents, int timeout);

            [DllImport(Lib, SetLastError = true)]
            public static extern int ioctl(int fd, uint request, ref IfReq ifr);

            [DllImport(Lib, SetLastError = true)]
            public static extern int ioctl(int fd, uint request, ref ifreq_addr ifr);

            [DllImport(Lib, SetLastError = true)]
            public static extern int ioctl(int fd, uint request, ref ifreq_index ifr);

            public const int O_RDWR = 2;
            public const int F_GETFL = 3;
            public const int F_SETFL = 4;
            public const int O_NONBLOCK = 0x800;

            public const int AF_INET = 2;
            public const int SOCK_DGRAM = 2;

            public const uint TUNSETIFF = 0x400454CA;
            public const short IFF_TUN = 0x0001;
            public const short IFF_NO_PI = 0x1000;
            public const short IFF_UP = 0x0001;
            public const short IFF_RUNNING = 0x0040;

            public const uint SIOCSIFADDR = 0x8916;
            public const uint SIOCSIFNETMASK = 0x891C;
            public const uint SIOCGIFFLAGS = 0x8913;
            public const uint SIOCSIFFLAGS = 0x8914;
            public const uint SIOCGIFINDEX = 0x8933;

            public const int EPOLL_CTL_ADD = 1;
            public const uint EPOLLIN = 0x001;

            public const int EINTR = 4;
            public const int EAGAIN = 11;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IfReq
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
            public string ifr_name;
            public short ifr_flags;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 22)]
            public byte[] padding;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct sockaddr_in
        {
            public short sin_family;
            public ushort sin_port;
            public uint sin_addr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] sin_zero;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct ifreq_addr
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
            public string ifr_name;
            public sockaddr_in addr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] padding;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct ifreq_index
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
            public string ifr_name;
            public int ifr_ifindex;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
            public byte[] padding;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct epoll_event
        {
            public uint events;
            public ulong data;
        }

        private const string DeviceName = "Tunnel";
        private const int MaxPacket = 65535;

        private static readonly byte[] _wake = new byte[8] { 1, 0, 0, 0, 0, 0, 0, 0 };

        private int _fd = -1;
        private int _epfd = -1;
        private int _eventFd = -1;
        private int _disposed = 0;
        private Task? _readLoop;
        private Task? _routeWorker;
        private readonly PeerRouteTracker _peerRoutes = new();

        private readonly Channel<string> _routeQueue = Channel.CreateBounded<string>(
            new BoundedChannelOptions(256)
            {
                FullMode = BoundedChannelFullMode.DropWrite,
                SingleReader = true
            });

        private static ILogger? logger => Program.logger;

        public uint interfaceIndex { get; private set; }
        public string tunnelIp { get; private set; } = "";

        public Task InitAsync(string ip, CancellationToken ct = default)
        {
            if (_fd >= 0)
                throw new InvalidOperationException("Already initialized");

            _fd = Libc.open("/dev/net/tun", Libc.O_RDWR);
            if (_fd < 0)
                throw new IOException($"open /dev/net/tun failed: errno={Marshal.GetLastWin32Error()}");

            try
            {
                var ifr = new IfReq
                {
                    ifr_name = DeviceName,
                    ifr_flags = (short)(Libc.IFF_TUN | Libc.IFF_NO_PI),
                    padding = new byte[22]
                };
                if (Libc.ioctl(_fd, Libc.TUNSETIFF, ref ifr) < 0)
                    throw new IOException($"ioctl TUNSETIFF failed: errno={Marshal.GetLastWin32Error()}");

                int flags = Libc.fcntl(_fd, Libc.F_GETFL, 0);
                if (flags < 0 || Libc.fcntl(_fd, Libc.F_SETFL, flags | Libc.O_NONBLOCK) < 0)
                    throw new IOException($"fcntl O_NONBLOCK failed: errno={Marshal.GetLastWin32Error()}");

                ConfigureInterface(DeviceName, ip);

                _eventFd = Libc.eventfd(0, 0);
                if (_eventFd < 0)
                    throw new IOException($"eventfd failed: errno={Marshal.GetLastWin32Error()}");

                _epfd = Libc.epoll_create1(0);
                if (_epfd < 0)
                    throw new IOException($"epoll_create1 failed: errno={Marshal.GetLastWin32Error()}");

                var evTun = new epoll_event { events = Libc.EPOLLIN, data = (ulong)(long)_fd };
                if (Libc.epoll_ctl(_epfd, Libc.EPOLL_CTL_ADD, _fd, ref evTun) < 0)
                    throw new IOException($"epoll_ctl tun failed: errno={Marshal.GetLastWin32Error()}");

                var evEvt = new epoll_event { events = Libc.EPOLLIN, data = (ulong)(long)_eventFd };
                if (Libc.epoll_ctl(_epfd, Libc.EPOLL_CTL_ADD, _eventFd, ref evEvt) < 0)
                    throw new IOException($"epoll_ctl eventfd failed: errno={Marshal.GetLastWin32Error()}");

                tunnelIp = ip;
                _peerRoutes.SetTunnelIp(PeerRouteTracker.ParseIp(ip));
                _routeWorker = Task.Run(() => RouteWorkerAsync(ct), ct);
                logger?.LogInformation($"TUN {DeviceName} 已就绪: {ip}/32 ifindex={interfaceIndex}");
            }
            catch
            {
                Cleanup();
                throw;
            }

            return Task.CompletedTask;
        }

        private void ConfigureInterface(string name, string ip)
        {
            int sock = Libc.socket(Libc.AF_INET, Libc.SOCK_DGRAM, 0);
            if (sock < 0)
                throw new IOException($"socket failed: errno={Marshal.GetLastWin32Error()}");

            try
            {
                var addrReq = new ifreq_addr
                {
                    ifr_name = name,
                    addr = new sockaddr_in
                    {
                        sin_family = Libc.AF_INET,
                        sin_port = 0,
                        sin_addr = IpToInAddr(ip),
                        sin_zero = new byte[8]
                    },
                    padding = new byte[8]
                };
                if (Libc.ioctl(sock, Libc.SIOCSIFADDR, ref addrReq) < 0)
                    throw new IOException($"SIOCSIFADDR failed: errno={Marshal.GetLastWin32Error()}");

                var maskReq = new ifreq_addr
                {
                    ifr_name = name,
                    addr = new sockaddr_in
                    {
                        sin_family = Libc.AF_INET,
                        sin_addr = 0xFFFFFFFF,
                        sin_zero = new byte[8]
                    },
                    padding = new byte[8]
                };
                if (Libc.ioctl(sock, Libc.SIOCSIFNETMASK, ref maskReq) < 0)
                    throw new IOException($"SIOCSIFNETMASK failed: errno={Marshal.GetLastWin32Error()}");

                var flagReq = new IfReq { ifr_name = name, padding = new byte[22] };
                if (Libc.ioctl(sock, Libc.SIOCGIFFLAGS, ref flagReq) < 0)
                    throw new IOException($"SIOCGIFFLAGS failed: errno={Marshal.GetLastWin32Error()}");

                flagReq.ifr_flags |= (short)(Libc.IFF_UP | Libc.IFF_RUNNING);
                if (Libc.ioctl(sock, Libc.SIOCSIFFLAGS, ref flagReq) < 0)
                    throw new IOException($"SIOCSIFFLAGS failed: errno={Marshal.GetLastWin32Error()}");

                var idxReq = new ifreq_index { ifr_name = name, padding = new byte[20] };
                if (Libc.ioctl(sock, Libc.SIOCGIFINDEX, ref idxReq) < 0)
                    throw new IOException($"SIOCGIFINDEX failed: errno={Marshal.GetLastWin32Error()}");

                interfaceIndex = (uint)idxReq.ifr_ifindex;
            }
            finally
            {
                Libc.close(sock);
            }
        }

        public Task ReadAsync(Channel<PacketBuffer> channel, CancellationToken ct)
        {
            ct.Register(SignalShutdown);
            _readLoop = Task.Run(() => EpollLoop(channel, ct));
            return _readLoop;
        }

        private async Task EpollLoop(Channel<PacketBuffer> channel, CancellationToken ct)
        {
            var events = new epoll_event[8];

            while (Volatile.Read(ref _disposed) == 0 && !ct.IsCancellationRequested)
            {
                int n = Libc.epoll_wait(_epfd, events, events.Length, -1);
                if (n < 0)
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err == Libc.EINTR) continue;
                    logger?.LogWarning($"[READ] epoll_wait failed: errno={err}");
                    break;
                }

                bool wake = false, tunReadable = false;
                for (int i = 0; i < n; i++)
                {
                    long s = (long)events[i].data;
                    if (s == _eventFd) wake = true;
                    else if (s == _fd) tunReadable = true;
                }

                if (wake) break;
                if (tunReadable) await DrainTun(channel, ct);
            }
        }

        private async Task DrainTun(Channel<PacketBuffer> channel, CancellationToken ct)
        {
            while (Volatile.Read(ref _disposed) == 0 && !ct.IsCancellationRequested)
            {
                var buf = PacketBuffer.Rent(MaxPacket);
                int n = Libc.read(_fd, buf.Buffer, MaxPacket);
                if (n < 0)
                {
                    buf.Dispose();
                    int err = Marshal.GetLastWin32Error();
                    if (err == Libc.EAGAIN) return;
                    if (err == Libc.EINTR) continue;
                    logger?.LogWarning($"[READ] read failed: errno={err}");
                    return;
                }

                if (n == 0)
                {
                    buf.Dispose();
                    return;
                }

                // 直接复用读入的大 buffer,仅设置实际长度,避免二次拷贝
                buf.SetLength(n);

                if (!PacketFilter.ShouldForward(buf.ReadOnlyMemory.Span))
                {
                    buf.Dispose();
                    continue;
                }

                // 队列满则丢弃新包(不阻塞读取线程),并计数
                if (!channel.Writer.TryWrite(buf))
                {
                    buf.Dispose();
                    TunnelStats.IncrementChannelDrops();
                }
            }
        }

        public Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
        {
            EnsurePeerRoute(data.Span);

            int written = WriteToFd(data);
            if (written < 0)
            {
                int err = Marshal.GetLastWin32Error();
                if (err == Libc.EAGAIN || err == Libc.EINTR)
                    return Task.CompletedTask;
                logger?.LogWarning($"[WRITE] write failed: errno={err}");
                TunnelStats.IncrementSinkWriteFailures();
            }

            return Task.CompletedTask;
        }

        private unsafe int WriteToFd(ReadOnlyMemory<byte> data)
        {
            using var handle = data.Pin();
            return Libc.write(_fd, (IntPtr)handle.Pointer, data.Length);
        }

        // 出口热路径只做注册判断 + 入队,真正的 ip route 调用在后台 worker 执行,避免阻塞写包。
        private void EnsurePeerRoute(ReadOnlySpan<byte> packet)
        {
            if (interfaceIndex == 0) return;
            if (!_peerRoutes.TryRegister(packet, out var srcIp)) return;

            if (_routeQueue.Writer.TryWrite(srcIp))
                TunnelStats.IncrementRouteUpdatesQueued();
        }

        private async Task RouteWorkerAsync(CancellationToken ct)
        {
            try
            {
                await foreach (var srcIp in _routeQueue.Reader.ReadAllAsync(ct))
                    await RunCommandAsync("ip", $"route replace {srcIp}/32 dev {DeviceName}", ct);
            }
            catch (OperationCanceledException) { }
        }

        private void SignalShutdown()
        {
            int fd = _eventFd;
            if (fd >= 0) Libc.write(fd, _wake, 8);
        }

        private static uint IpToInAddr(string ip)
        {
            Span<byte> bytes = stackalloc byte[4];
            if (!System.Net.IPAddress.TryParse(ip, out var address)
                || !address.TryWriteBytes(bytes, out int written)
                || written != 4)
                throw new InvalidOperationException($"Invalid IPv4 address: {ip}");

            return BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;

            SignalShutdown();

            var loop = _readLoop;
            if (loop != null)
            {
                try { await loop.ConfigureAwait(false); }
                catch { }
            }

            Cleanup();
        }

        private void Cleanup()
        {
            if (_epfd >= 0) { Libc.close(_epfd); _epfd = -1; }
            if (_eventFd >= 0) { Libc.close(_eventFd); _eventFd = -1; }
            if (_fd >= 0) { Libc.close(_fd); _fd = -1; }
        }

        private static async Task RunCommandAsync(string cmd, string args, CancellationToken ct = default)
        {
            var psi = new ProcessStartInfo(cmd, args)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var p = Process.Start(psi)!;
            await p.WaitForExitAsync(ct);
            if (p.ExitCode != 0)
            {
                logger?.LogWarning($"[CMD] {cmd} {args} exit={p.ExitCode}");
                TunnelStats.IncrementRouteUpdateFailures();
            }
        }
    }
}
