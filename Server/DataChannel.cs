using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace TunRelayServer
{
    /// <summary>
    /// 微批处理参数。构造时做边界归一化。
    /// </summary>
    public sealed class BatchOptions
    {
        public int DelayMs { get; }
        public int MaxBytes { get; }
        public int MaxPackets { get; }

        public BatchOptions(int delayMs, int maxBytes, int maxPackets)
        {
            DelayMs = Math.Clamp(delayMs, 0, 3);
            MaxBytes = Math.Clamp(maxBytes, 4096, 262144);
            MaxPackets = Math.Clamp(maxPackets, 1, 128);
        }
    }

    /// <summary>
    /// 数据通道 v2 batch 帧的编码/解码。
    /// 帧格式: [frameLength:4 BE][frameType:1][packetCount:2 BE]( [packetLength:2 BE][packet bytes] )*
    /// frameLength 不含自身。发送端聚合,接收端解析后直接逐包写出口。
    /// </summary>
    public static class DataChannel
    {
        public const byte FrameTypePacketBatch = 1;
        public const int MaxFrameBytes = 1024 * 1024;
        private const int TraceDumpBytes = 64;

        private static ILogger? logger => Program.logger;

        /// <summary>
        /// 发送循环: 从单包 channel 聚合一个 batch,通过 PipeWriter 一次写入并 flush 到 TLS。
        /// </summary>
        public static async Task SendLoopAsync(
            ChannelReader<PacketBuffer> reader,
            Stream sslStream,
            BatchOptions opt,
            CancellationToken ct)
        {
            var writer = PipeWriter.Create(sslStream, new StreamPipeWriterOptions(leaveOpen: true));
            var batch = new List<PacketBuffer>(opt.MaxPackets);
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    PacketBuffer first;
                    try
                    {
                        first = await reader.ReadAsync(ct);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }

                    batch.Add(first);
                    long bytes = first.Length;

                    while (batch.Count < opt.MaxPackets && bytes < opt.MaxBytes
                           && reader.TryRead(out var more))
                    {
                        batch.Add(more);
                        bytes += more.Length;
                    }

                    if (opt.DelayMs > 0 && batch.Count < opt.MaxPackets && bytes < opt.MaxBytes)
                    {
                        using var delayCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                        delayCts.CancelAfter(opt.DelayMs);
                        try
                        {
                            while (batch.Count < opt.MaxPackets && bytes < opt.MaxBytes)
                            {
                                var more = await reader.ReadAsync(delayCts.Token);
                                batch.Add(more);
                                bytes += more.Length;
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            // 窗口超时或正在关闭
                        }
                    }

                    if (ct.IsCancellationRequested)
                        break;

                    WriteBatch(writer, batch);
                    await writer.FlushAsync(ct);

                    TunnelStats.AddBatchSent(batch.Count);
                    bool trace = logger?.IsEnabled(LogLevel.Trace) ?? false;
                    foreach (var p in batch)
                    {
                        TunnelStats.AddSent(p.Length);
                        if (trace)
                            logger?.LogTrace("[Send] len={Len} {Hex}", p.Length, HexDump(p.ReadOnlyMemory.Span));
                        p.Dispose();
                    }
                    batch.Clear();
                }
            }
            finally
            {
                foreach (var p in batch)
                    p.Dispose();
                await writer.CompleteAsync();
            }
        }

        private static void WriteBatch(PipeWriter writer, List<PacketBuffer> batch)
        {
            int payload = 1 + 2;
            foreach (var p in batch)
                payload += 2 + p.Length;

            Span<byte> frameHeader = writer.GetSpan(7);
            BinaryPrimitives.WriteInt32BigEndian(frameHeader, payload);
            frameHeader[4] = FrameTypePacketBatch;
            BinaryPrimitives.WriteUInt16BigEndian(frameHeader.Slice(5), (ushort)batch.Count);
            writer.Advance(7);
            
            foreach (var p in batch)
            {
                Span<byte> packetHeader = writer.GetSpan(2);
                BinaryPrimitives.WriteUInt16BigEndian(packetHeader, (ushort)p.Length);
                writer.Advance(2);
                WritePacket(writer, p.ReadOnlyMemory);
            }
        }

        private static void WritePacket(PipeWriter writer, ReadOnlyMemory<byte> packet)
        {
            while (!packet.IsEmpty)
            {
                Memory<byte> destination = writer.GetMemory(packet.Length);
                int count = Math.Min(destination.Length, packet.Length);
                packet.Slice(0, count).CopyTo(destination);
                writer.Advance(count);
                packet = packet.Slice(count);
            }
        }

        /// <summary>
        /// 接收循环: 从 PipeReader 解析完整 batch 帧,解出的 packet slice 立即顺序交给 sink 写出口。
        /// 协议错误会抛出 InvalidDataException 以断开会话;单包 sink 失败会被记录并跳过。
        /// </summary>
        public static async Task ReceiveLoopAsync(
            Stream sslStream,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> sink,
            CancellationToken ct)
        {
            var reader = PipeReader.Create(sslStream, new StreamPipeReaderOptions(leaveOpen: true));
            try
            {
                while (true)
                {
                    ReadResult result;
                    try
                    {
                        result = await reader.ReadAsync(ct);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }

                    var buffer = result.Buffer;
                    while (TryReadFrame(ref buffer, out var frame))
                        await ProcessFrameAsync(frame, sink, ct);

                    reader.AdvanceTo(buffer.Start, buffer.End);

                    if (result.IsCompleted)
                    {
                        if (!buffer.IsEmpty)
                        {
                            TunnelStats.IncrementProtocolErrors();
                            throw new InvalidDataException("连接结束时存在不完整的残帧");
                        }
                        break;
                    }
                }
            }
            finally
            {
                await reader.CompleteAsync();
            }
        }

        private static bool TryReadFrame(ref ReadOnlySequence<byte> buffer, out ReadOnlySequence<byte> frame)
        {
            frame = default;
            if (buffer.Length < 4)
                return false;

            Span<byte> lenBuf = stackalloc byte[4];
            buffer.Slice(0, 4).CopyTo(lenBuf);
            int frameLen = BinaryPrimitives.ReadInt32BigEndian(lenBuf);

            if (frameLen <= 0 || frameLen > MaxFrameBytes)
            {
                TunnelStats.IncrementProtocolErrors();
                throw new InvalidDataException($"非法帧长度: {frameLen}");
            }

            if (buffer.Length < 4 + frameLen)
                return false;

            frame = buffer.Slice(4, frameLen);
            buffer = buffer.Slice(4 + frameLen);
            return true;
        }

        private static async ValueTask ProcessFrameAsync(
            ReadOnlySequence<byte> frame,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> sink,
            CancellationToken ct)
        {
            long pos = 0;

            byte type = ReadU8(frame, pos);
            pos += 1;
            if (type != FrameTypePacketBatch)
            {
                TunnelStats.IncrementProtocolErrors();
                throw new InvalidDataException($"非法帧类型: {type}");
            }

            ushort count = ReadU16(frame, pos);
            pos += 2;
            if (count == 0)
            {
                TunnelStats.IncrementProtocolErrors();
                throw new InvalidDataException("空 batch");
            }

            TunnelStats.AddBatchReceived();
            bool trace = logger?.IsEnabled(LogLevel.Trace) ?? false;

            for (int i = 0; i < count; i++)
            {
                if (frame.Length - pos < 2)
                {
                    TunnelStats.IncrementProtocolErrors();
                    throw new InvalidDataException("packet 长度字段被截断");
                }

                ushort pktLen = ReadU16(frame, pos);
                pos += 2;
                if (pktLen < 20)
                {
                    TunnelStats.IncrementProtocolErrors();
                    throw new InvalidDataException($"packet 过小: {pktLen}");
                }
                if (frame.Length - pos < pktLen)
                {
                    TunnelStats.IncrementProtocolErrors();
                    throw new InvalidDataException("packet 内容被截断");
                }

                var pktSeq = frame.Slice(pos, pktLen);
                pos += pktLen;

                byte[]? pooled = null;
                ReadOnlyMemory<byte> mem;
                if (pktSeq.IsSingleSegment)
                {
                    mem = pktSeq.First;
                }
                else
                {
                    pooled = ArrayPool<byte>.Shared.Rent(pktLen);
                    pktSeq.CopyTo(pooled);
                    mem = pooled.AsMemory(0, pktLen);
                }

                TunnelStats.AddReceived(pktLen);
                if (trace)
                    logger?.LogTrace("[Recv] len={Len} {Hex}", pktLen, HexDump(mem.Span));

                try
                {
                    await sink(mem, ct);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    TunnelStats.IncrementSinkWriteFailures();
                    logger?.LogDebug($"[SINK] 单包写出口失败: {ex.Message}");
                }
                finally
                {
                    if (pooled != null)
                        ArrayPool<byte>.Shared.Return(pooled);
                }
            }

            if (pos != frame.Length)
            {
                TunnelStats.IncrementProtocolErrors();
                throw new InvalidDataException("batch 内 packet 长度累加与帧长度不一致");
            }
        }

        private static byte ReadU8(ReadOnlySequence<byte> seq, long offset)
        {
            Span<byte> tmp = stackalloc byte[1];
            seq.Slice(offset, 1).CopyTo(tmp);
            return tmp[0];
        }

        private static ushort ReadU16(ReadOnlySequence<byte> seq, long offset)
        {
            Span<byte> tmp = stackalloc byte[2];
            seq.Slice(offset, 2).CopyTo(tmp);
            return BinaryPrimitives.ReadUInt16BigEndian(tmp);
        }

        private static string HexDump(ReadOnlySpan<byte> span)
        {
            int n = Math.Min(TraceDumpBytes, span.Length);
            return Convert.ToHexString(span.Slice(0, n));
        }
    }
}
