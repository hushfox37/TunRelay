using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace TunRelayClient
{
    internal sealed class ControlSession
    {
        public TunnelNet Net { get; init; } = null!;
        public ServerAssignment Assignment { get; init; } = null!;
    }

    internal sealed class ControlHandshake
    {
        private readonly TunRelayConfig _config;
        private readonly ILogger _logger;

        public ControlHandshake(TunRelayConfig config, ILogger logger)
        {
            _config = config;
            _logger = logger;
        }

        public async Task<ControlSession> ConnectWithRetryAsync(
            ReconnectPolicy reconnectPolicy,
            CancellationToken ct,
            string? expectedTunnelIp = null,
            int? expectedUplink = null,
            int? expectedDownlink = null)
        {
            while (true)
            {
                TunnelNet? net = null;
                try
                {
                    net = new TunnelNet(Program.ServerIP, Program.ServerPort);
                    Program.tunnelNet = net;

                    _logger.LogInformation("正在连接服务器...");
                    await net.ConnectControlAsync(ct);
                    _logger.LogInformation("服务器控制连接已建立");

                    if (!await AuthenticateAsync(net, ct))
                    {
                        throw new InvalidOperationException("认证失败");
                    }

                    _logger.LogInformation("认证成功");
                    var assignment = await ReceiveServerAssignmentAsync(net, ct);
                    // 首次握手后 TUN 已完成配置，重连时不能接受不兼容的下发参数。
                    ValidateExpectedAssignment(assignment, expectedTunnelIp, expectedUplink, expectedDownlink);

                    return new ControlSession { Net = net, Assignment = assignment };
                }
                catch (OperationCanceledException)
                {
                    net?.Close();
                    throw;
                }
                catch (Exception ex)
                {
                    net?.Close();
                    int attempts = reconnectPolicy.RecordFailure();
                    if (reconnectPolicy.HasReachedLimit)
                    {
                        _logger.LogError(ex, $"连接服务器失败，已达到重连上限 {reconnectPolicy.MaxAttempts}");
                        throw;
                    }

                    _logger.LogError(ex, $"连接服务器失败，第 {attempts} 次/上限 {reconnectPolicy.LimitText}，{(int)reconnectPolicy.Delay.TotalMilliseconds} 毫秒后重试");
                    await Task.Delay(reconnectPolicy.Delay, ct);
                }
            }
        }

        private async Task<ServerAssignment> ReceiveServerAssignmentAsync(TunnelNet net, CancellationToken ct)
        {
            var data = await net.ReceiveControlAsync(ct);
            return ServerAssignment.Parse(data);
        }

        private static void ValidateExpectedAssignment(
            ServerAssignment assignment,
            string? expectedTunnelIp,
            int? expectedUplink,
            int? expectedDownlink)
        {
            if (expectedTunnelIp != null &&
                (!string.Equals(assignment.TunnelIp, expectedTunnelIp, StringComparison.Ordinal) ||
                 assignment.Uplink != expectedUplink ||
                 assignment.Downlink != expectedDownlink))
            {
                throw new InvalidOperationException(
                    $"重连下发参数变化: TunnelIP={assignment.TunnelIp}, Uplink={assignment.Uplink}, Downlink={assignment.Downlink}");
            }
        }

        private async Task<bool> AuthenticateAsync(TunnelNet tunnelNet, CancellationToken ct)
        {
            byte[] key = Encoding.UTF8.GetBytes(_config.Secret);
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string signData = $"{_config.ClientID}:{timestamp}";
            byte[] msg = Encoding.UTF8.GetBytes(signData);

            using var hmac = new HMACSHA256(key);

            string sign = Convert.ToHexString(hmac.ComputeHash(msg));
            var json = JsonSerializer.Serialize(
                new AuthenticationRequest { ClientID = _config.ClientID, Timestamp = timestamp, Sign = sign },
                TunRelayJsonContext.Default.AuthenticationRequest);

            _logger.LogInformation($"[AUTH] 发送认证 ClientID={_config.ClientID}, Timestamp={timestamp}");
            await tunnelNet.SendControlAsync(json, ct);
            var response = await tunnelNet.ReceiveControlAsync(ct);
            _logger.LogInformation($"[AUTH] 服务端响应: {response}");
            return response == "Success";
        }
    }
}
