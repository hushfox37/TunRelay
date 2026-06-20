using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace TunRelayServer
{
    static class NFQueue
    {
        static ILogger _logger;
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

        public static void Init(ILogger logger)
        {
            _logger = logger;
        }
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

            _logger?.LogInformation($"NFQUEUE {queueNum} 已启动");
        }

        static bool ShouldForwardToClient(PacketBuffer packet, byte[] tunnelIp)
        {
            if (packet.Length < 20)
                return false;

            if ((packet.Buffer[0] >> 4) != 4)
                return false;

            if (IsIpEqual(packet, 12, tunnelIp))
                return false;

            if (!IsIpEqual(packet, 16, tunnelIp))
                return false;

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
    }
}
