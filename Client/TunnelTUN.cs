using System.Collections.Generic;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;

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

    public interface ITunDriver : IAsyncDisposable
    {
        Task InitAsync(string ip, CancellationToken ct = default);
        Task ReadAsync(Channel<PacketBuffer> channel, CancellationToken ct);
        Task WriteAsync(PacketBuffer data, CancellationToken ct = default);
    }

    public static class TunDriverFactory
    {
        public static ITunDriver Create()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return new WintunDriver();
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return new LinuxunDriver();

            throw new PlatformNotSupportedException("Only Windows Wintun and Linux TUN");
        }
    }

    class TUN
    {
        private readonly ITunDriver Driver;
        public readonly Channel<PacketBuffer> RX_channel;
        public readonly Channel<PacketBuffer> TX_channel;

        public TUN(ITunDriver driver, Channel<PacketBuffer> rx_channel, Channel<PacketBuffer> tx_channel)
        {
            Driver = driver;
            RX_channel = rx_channel;
            TX_channel = tx_channel;
        }

        public async Task StartAsync(string ip, CancellationToken ct = default)
        {
            await Driver.InitAsync(ip, ct);
            _ = Task.Run(() => Driver.ReadAsync(RX_channel, ct), ct);
            _ = Task.Run(() => ChannelToTunAsync(ct), ct);
        }

        private async Task ChannelToTunAsync(CancellationToken ct)
        {
            await foreach (var data in TX_channel.Reader.ReadAllAsync(ct))
            {
                using (data)
                {
                    await Driver.WriteAsync(data, ct);
                }
            }
        }
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

        private readonly object _peerRouteLock = new();
        private readonly HashSet<string> _peerRoutes = new();

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
                throw new InvalidOperationException($"CreateAdapter 失败，错误码: {err}");
            }

            getAdapterLUID(_adapter, out ulong LUID);
            SetIPv4Address(LUID, ip, 32);

            var netLUID = new NET_LUID { Value = LUID };
            uint idx = 0;
            uint indexResult = ConvertInterfaceLuidToIndex(ref netLUID, out idx);
            if (indexResult != 0)
                Console.WriteLine($"ConvertInterfaceLuidToIndex failed: {indexResult}");
            else
                Console.WriteLine($"WinTun interface index: {idx}");

            _session = startSession(_adapter, 0x400000);
            _readWaitEvent = getReadWaitEvent(_session);

            tunnelIp = ip;
            interfaceIndex = idx;

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
                Console.WriteLine($"设置IP失败,错误码: {result}");
            else
                Console.WriteLine($"IP设置成功: {ip}/{prefixLength}");
        }

        public async Task ReadAsync(Channel<PacketBuffer> channel, CancellationToken ct)
        {
            await foreach (var packet in ReadPacketsAsync(ct))
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

        public async Task WriteAsync(PacketBuffer data, CancellationToken ct = default)
        {
            EnsurePeerRoute(data);

            int spin = 0;
            while (!ct.IsCancellationRequested)
            {
                var ptr = _allocateSendPacket(_session, (uint)data.Length);
                if (ptr != IntPtr.Zero)
                {
                    Marshal.Copy(data.Buffer, 0, ptr, data.Length);
                    _sendPacket(_session, ptr);
                    return;
                }

                if (spin++ < 10) Thread.SpinWait(20);
                else await Task.Yield();
            }
        }

        private void EnsurePeerRoute(PacketBuffer packet)
        {
            if (interfaceIndex == 0) return;
            if (packet.Length < 20 || packet.Buffer[0] >> 4 != 4) return;

            var src = $"{packet.Buffer[12]}.{packet.Buffer[13]}.{packet.Buffer[14]}.{packet.Buffer[15]}";
            var dst = $"{packet.Buffer[16]}.{packet.Buffer[17]}.{packet.Buffer[18]}.{packet.Buffer[19]}";
            if (dst != tunnelIp || src == tunnelIp || src == dst) return;

            lock (_peerRouteLock)
            {
                if (!_peerRoutes.Add(src)) return;
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
                    Console.WriteLine($"[ROUTE] failed to start route.exe for {src}/32");
                    return;
                }

                process.WaitForExit(3000);
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                if (process.ExitCode == 0)
                    Console.WriteLine($"[ROUTE] {src}/32 -> if {interfaceIndex}");
                else
                    Console.WriteLine($"[ROUTE] failed {src}/32 -> if {interfaceIndex} exit={process.ExitCode} {output}{error}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ROUTE] exception {src}/32 -> if {interfaceIndex}: {ex.Message}");
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
    public class LinuxunDriver : ITunDriver
    {
        static class Libc
        {
            const string Lib = "libc";

            [DllImport(Lib, SetLastError = true)]
            public static extern int open(string path, int flags);

            [DllImport(Lib, SetLastError = true)]
            public static extern int ioctl(int fd, uint request, ref ifreq ifr);

            [DllImport(Lib, SetLastError = true)]
            public static extern int close(int fd);

            public const int O_RDWR = 2;
            public const uint TUNSETIFF = 0x400454CA;
            public const short IFF_TUN = 0x0001;
            public const short IFF_NO_PI = 0x1000;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct ifreq
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
            public string ifr_name;  // 设备名，如 "tun0"
            public short ifr_flags;
            // padding 到 40 字节（ifreq 实际大小）
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 22)]
            public byte[] padding;
        }
        private int _fd = -1;
        private FileStream? _stream;
        private readonly object _peerRouteLock = new();
        private readonly HashSet<uint> _peerRoutes = new();
        private int _disposed = 0;
        private uint _tunnelIpUint;

        public uint interfaceIndex { get; private set; }
        public string tunnelIp { get; private set; } = "";

        public async Task InitAsync(string ip, CancellationToken ct = default)
        {
            if (_fd >= 0)
                throw new InvalidOperationException("Already initialized");

            _fd = Libc.open("/dev/net/tun", Libc.O_RDWR);
            if (_fd < 0)
                throw new IOException($"open failed: {Marshal.GetLastWin32Error()}");

            // 2. 配置 ifreq，绑定名称和模式
            var ifr = new ifreq
            {
                ifr_name = "Tunnel",
                ifr_flags = Libc.IFF_TUN | Libc.IFF_NO_PI,
                padding = new byte[22]
            };

            if (Libc.ioctl(_fd, Libc.TUNSETIFF, ref ifr) < 0)
                throw new IOException($"ioctl TUNSETIFF failed: {Marshal.GetLastWin32Error()}");

            _stream = new FileStream(
                new SafeFileHandle((IntPtr)_fd, ownsHandle: true),
                FileAccess.ReadWrite,
                bufferSize: 65536,
                isAsync: false
            );

            tunnelIp = ip;
            _tunnelIpUint = IpToUInt32(ip);

            await RunCommandAsync("ip", $"addr add {ip}/32 dev Tunnel", ct);
            await RunCommandAsync("ip", "link set Tunnel up", ct);

            var idxStr = await File.ReadAllTextAsync("/sys/class/net/Tunnel/ifindex", ct);
            interfaceIndex = uint.Parse(idxStr.Trim());
        }

        public async Task ReadAsync(Channel<PacketBuffer> channel, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                PacketBuffer? buf = null;
                try
                {
                    buf = PacketBuffer.Rent(65535);
                    int n = await Task.Run(() => _stream!.Read(buf.Buffer, 0, buf.Buffer.Length), ct);
                    if (n <= 0)
                    {
                        buf.Dispose();
                        buf = null;
                        continue;
                    }

                    if (n < buf.Buffer.Length)
                    {
                        var exact = PacketBuffer.Rent(n);
                        Buffer.BlockCopy(buf.Buffer, 0, exact.Buffer, 0, n);
                        buf.Dispose();
                        buf = exact;
                    }

                    if (buf.Length < 20
                        || buf.Buffer[0] >> 4 != 4
                        || (buf.Buffer[9] != Protocol.TCP && buf.Buffer[9] != Protocol.UDP))
                    {
                        buf.Dispose();
                        continue;
                    }

                    byte d1 = buf.Buffer[16], d4 = buf.Buffer[19];
                    if (d1 is >= 224 and <= 239 || d4 == 255)
                    {
                        buf.Dispose();
                        continue;
                    }

                    await channel.Writer.WriteAsync(buf, ct);
                    buf = null;
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    buf?.Dispose();
                    Console.WriteLine($"[READ] error: {ex.Message}, retrying...");
                    await Task.Delay(500, ct);
                }
            }
        }

        public async Task WriteAsync(PacketBuffer data, CancellationToken ct = default)
        {
            await EnsurePeerRouteAsync(data, ct);

            await Task.Run(() => _stream!.Write(data.Buffer, 0, data.Length), ct);
        }

        private async Task EnsurePeerRouteAsync(PacketBuffer packet, CancellationToken ct = default)
        {
            if (interfaceIndex == 0) return;
            if (packet.Length < 20 || packet.Buffer[0] >> 4 != 4) return;

            uint src = BinaryPrimitives.ReadUInt32BigEndian(packet.Buffer.AsSpan(12));
            uint dst = BinaryPrimitives.ReadUInt32BigEndian(packet.Buffer.AsSpan(16));
            if (dst != _tunnelIpUint || src == _tunnelIpUint || src == dst) return;

            lock (_peerRouteLock)
            {
                if (!_peerRoutes.Add(src)) return;
            }

            var srcIp = UInt32ToIp(src);
            await RunCommandAsync("ip", $"route replace {srcIp}/32 dev Tunnel", ct);
        }

        private static uint IpToUInt32(string ip)
        {
            Span<byte> bytes = stackalloc byte[4];
            if (!System.Net.IPAddress.TryParse(ip, out var address)
                || !address.TryWriteBytes(bytes, out int written)
                || written != 4)
                throw new InvalidOperationException($"Invalid IPv4 address: {ip}");

            return BinaryPrimitives.ReadUInt32BigEndian(bytes);
        }

        private static string UInt32ToIp(uint ip)
        {
            return $"{(ip >> 24) & 0xff}.{(ip >> 16) & 0xff}.{(ip >> 8) & 0xff}.{ip & 0xff}";
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;

            if (_stream != null)
            {
                await _stream.DisposeAsync();
                _stream = null;
                _fd = -1;
            }
            else if (_fd >= 0)
            {
                Libc.close(_fd);
                _fd = -1;
            }
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
                Console.WriteLine($"[CMD] {cmd} {args} exit={p.ExitCode}");
        }
    }
}
