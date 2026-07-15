using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace TunRelayServer;

internal static class NFQueue
{
    private const int NetlinkMessageBufferSize = 131072;
    private const int SocketReceiveBufferSize = 4 * 1024 * 1024;
    private const int SolSocket = 1;
    private const int SoReceiveBuffer = 8;

    private static ILogger? _logger;

    [DllImport("libnetfilter_queue.so.1")]
    private static extern IntPtr nfq_open();

    [DllImport("libnetfilter_queue.so.1")]
    private static extern int nfq_bind_pf(IntPtr handle, ushort protocolFamily);

    [DllImport("libnetfilter_queue.so.1")]
    private static extern IntPtr nfq_create_queue(IntPtr handle, ushort number, NfqCallback callback, IntPtr data);

    [DllImport("libnetfilter_queue.so.1")]
    private static extern int nfq_set_mode(IntPtr queueHandle, byte mode, uint range);

    [DllImport("libnetfilter_queue.so.1")]
    private static extern int nfq_set_verdict(IntPtr queueHandle, uint id, uint verdict, uint dataLength, IntPtr buffer);

    [DllImport("libnetfilter_queue.so.1")]
    private static extern int nfq_fd(IntPtr handle);

    [DllImport("libnetfilter_queue.so.1")]
    private static extern int nfq_handle_packet(IntPtr handle, byte[] buffer, int length);

    [DllImport("libnetfilter_queue.so.1")]
    private static extern int nfq_get_payload(IntPtr data, out IntPtr payload);

    [DllImport("libnetfilter_queue.so.1")]
    private static extern IntPtr nfq_get_msg_packet_hdr(IntPtr data);

    [DllImport("libc.so.6", EntryPoint = "recv", SetLastError = true)]
    private static extern int recv(int fd, byte[] buffer, int length, int flags);

    [DllImport("libc.so.6", EntryPoint = "setsockopt", SetLastError = true)]
    private static extern int setsockopt(int fd, int level, int option, ref int value, uint valueLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int NfqCallback(IntPtr queueHandle, IntPtr message, IntPtr data, IntPtr context);

    private static IntPtr _handle;
    private static IntPtr _queueHandle;
    private static NfqCallback _callback = null!;

    public static void Init(ILogger logger) => _logger = logger;

    public static void Start(
        ushort queueNumber,
        string tunnelIp,
        Channel<PacketBuffer>[] transmitChannels,
        CancellationToken cancellationToken)
    {
        byte[] tunnelIpBytes = IPAddress.Parse(tunnelIp).GetAddressBytes();
        byte[]? activeNetlinkBatch = null;
        int activeNetlinkBatchLength = 0;

        _handle = nfq_open();
        if (_handle == IntPtr.Zero)
            throw new InvalidOperationException("nfq_open failed");
        if (nfq_bind_pf(_handle, 2) < 0)
            throw new InvalidOperationException("nfq_bind_pf(AF_INET) failed");

        _callback = (queueHandle, _, data, _) =>
        {
            IntPtr header = nfq_get_msg_packet_hdr(data);
            uint packetId = (uint)IPAddress.NetworkToHostOrder(Marshal.ReadInt32(header));

            int capturedLength = nfq_get_payload(data, out IntPtr payload);
            if (capturedLength > 0)
            {
                uint originalLength = (uint)capturedLength;
                if (activeNetlinkBatch != null
                    && NfQueueNetlinkMetadata.TryGetOriginalLength(
                        activeNetlinkBatch.AsSpan(0, activeNetlinkBatchLength),
                        packetId,
                        out uint metadataLength))
                {
                    originalLength = metadataLength;
                }

                if (NfQueuePacketCapture.TryCapture(
                    payload,
                    capturedLength,
                    originalLength,
                    out PacketBuffer? packet))
                {
                    ForwardOrDispose(packet!, tunnelIpBytes, transmitChannels);
                }
                else
                {
                    LogTruncatedPacket(capturedLength, originalLength);
                }
            }

            nfq_set_verdict(queueHandle, packetId, 0, 0, IntPtr.Zero);
            return 0;
        };

        _queueHandle = nfq_create_queue(_handle, queueNumber, _callback, IntPtr.Zero);
        if (_queueHandle == IntPtr.Zero)
            throw new InvalidOperationException($"nfq_create_queue({queueNumber}) failed");
        if (nfq_set_mode(_queueHandle, 2, 65535) < 0)
            throw new InvalidOperationException("nfq_set_mode(NFQNL_COPY_PACKET) failed");

        int fd = nfq_fd(_handle);
        int receiveBufferSize = SocketReceiveBufferSize;
        if (setsockopt(fd, SolSocket, SoReceiveBuffer, ref receiveBufferSize, sizeof(int)) < 0)
        {
            int error = Marshal.GetLastPInvokeError();
            throw new InvalidOperationException(
                $"setsockopt(SO_RCVBUF={SocketReceiveBufferSize}) failed: errno={error}");
        }

        _ = Task.Run(() =>
        {
            var buffer = new byte[NetlinkMessageBufferSize];
            long receiveErrors = 0;

            while (!cancellationToken.IsCancellationRequested)
            {
                int receivedLength = recv(fd, buffer, buffer.Length, 0);
                if (receivedLength <= 0)
                {
                    if (receivedLength < 0)
                    {
                        receiveErrors++;
                        if (receiveErrors == 1 || receiveErrors % 1024 == 0)
                            _logger?.LogWarning("NFQUEUE recv failed: errno={Error}, total={Count}", Marshal.GetLastPInvokeError(), receiveErrors);
                    }
                    continue;
                }

                activeNetlinkBatch = buffer;
                activeNetlinkBatchLength = receivedLength;
                try
                {
                    if (nfq_handle_packet(_handle, buffer, receivedLength) < 0)
                        _logger?.LogWarning("nfq_handle_packet rejected a Netlink message");
                }
                finally
                {
                    activeNetlinkBatch = null;
                    activeNetlinkBatchLength = 0;
                }
            }
        }, cancellationToken);

        _logger?.LogInformation(
            "NFQUEUE {QueueNumber} started: messageBuffer={MessageBuffer}, socketReceiveBuffer={SocketBuffer}",
            queueNumber,
            NetlinkMessageBufferSize,
            SocketReceiveBufferSize);
    }

    private static void ForwardOrDispose(
        PacketBuffer packet,
        byte[] tunnelIp,
        Channel<PacketBuffer>[] transmitChannels)
    {
        if (!ShouldForwardToClient(packet, tunnelIp))
        {
            packet.Dispose();
            return;
        }

        var channel = transmitChannels[FlowHash.Index(packet.ReadOnlyMemory.Span, transmitChannels.Length)];
        if (!channel.Writer.TryWrite(packet))
        {
            packet.Dispose();
            TunnelStats.IncrementChannelDrops();
        }
    }

    private static void LogTruncatedPacket(int capturedLength, uint originalLength)
    {
        long count = TunnelStats.TruncatedPackets;
        if (count == 1 || count % 1024 == 0)
        {
            _logger?.LogWarning(
                "NFQUEUE dropped truncated packet: captured={CapturedLength}, original={OriginalLength}, total={Count}",
                capturedLength,
                originalLength,
                count);
        }
    }

    private static bool ShouldForwardToClient(PacketBuffer packet, byte[] tunnelIp)
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

    private static bool IsIpEqual(PacketBuffer packet, int offset, byte[] ip)
        => packet.Buffer[offset] == ip[0]
            && packet.Buffer[offset + 1] == ip[1]
            && packet.Buffer[offset + 2] == ip[2]
            && packet.Buffer[offset + 3] == ip[3];

    private static bool IsSameIp(PacketBuffer packet, int offsetA, int offsetB)
        => packet.Buffer[offsetA] == packet.Buffer[offsetB]
            && packet.Buffer[offsetA + 1] == packet.Buffer[offsetB + 1]
            && packet.Buffer[offsetA + 2] == packet.Buffer[offsetB + 2]
            && packet.Buffer[offsetA + 3] == packet.Buffer[offsetB + 3];
}
