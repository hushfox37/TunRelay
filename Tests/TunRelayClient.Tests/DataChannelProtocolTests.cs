using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using TunRelayClient;
using Xunit;

public sealed class DataChannelProtocolTests
{
    [Fact]
    public void MissingProtocolDefaultsToTls()
    {
        const string assignment = """
            {
              "TunnelIP": "203.0.113.1",
              "Ports": [19191],
              "UplinkConnections": 4,
              "DownlinkConnections": 4,
              "SessionId": "0123456789ABCDEF"
            }
            """;

        var parsed = ServerAssignment.Parse(assignment);

        Assert.Equal(DataChannelProtocol.Tls, parsed.Protocol);
    }

    [Fact]
    public void ParsesTcpProtocol()
    {
        const string assignment = """
            {
              "TunnelIP": "203.0.113.1",
              "Ports": [19191],
              "UplinkConnections": 4,
              "DownlinkConnections": 4,
              "SessionId": "0123456789ABCDEF",
              "Protocol": "tcp"
            }
            """;

        var parsed = ServerAssignment.Parse(assignment);

        Assert.Equal(DataChannelProtocol.Tcp, parsed.Protocol);
    }

    [Fact]
    public void UnknownProtocolIsRejectedAsFatalConfiguration()
    {
        var json = AssignmentJson("quic");

        Assert.Throws<UnsupportedDataChannelProtocolException>(() => ServerAssignment.Parse(json));
    }

    [Fact]
    public async Task TcpProtocolEstablishesPlainDataChannels()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        const string sessionId = "0123456789ABCDEF";

        var accepted = Task.WhenAll(ReadHandshakeAsync(listener), ReadHandshakeAsync(listener));
        var client = new TunnelNet(IPAddress.Loopback.ToString(), port);
        try
        {
            await client.ConnectDataChannelsAsync(1, 1, sessionId, DataChannelProtocol.Tcp);

            var handshakes = (await accepted).OrderBy(handshake => handshake.Role).ToArray();
            Assert.Collection(
                handshakes,
                handshake => Assert.Equal((sessionId, "rx", 0), handshake),
                handshake => Assert.Equal((sessionId, "tx", 0), handshake));
        }
        finally
        {
            client.Close();
            listener.Stop();
        }
    }

    [Fact]
    public void ChangedProtocolIsRejectedAsFatalConfiguration()
    {
        var initial = ServerAssignment.Parse(AssignmentJson("tls"));
        var reconnect = ServerAssignment.Parse(AssignmentJson("tcp"));

        Assert.Throws<DataChannelConfigurationException>(() => reconnect.EnsureCompatibleWith(initial));
    }

    private static string AssignmentJson(string protocol)
        => $$"""
            {
              "TunnelIP": "203.0.113.1",
              "Ports": [19191],
              "UplinkConnections": 4,
              "DownlinkConnections": 4,
              "SessionId": "0123456789ABCDEF",
              "Protocol": "{{protocol}}"
            }
            """;

    private static async Task<(string SessionId, string Role, int Index)> ReadHandshakeAsync(TcpListener listener)
    {
        using var tcp = await listener.AcceptTcpClientAsync();
        await using var stream = tcp.GetStream();
        byte[] length = new byte[4];
        await stream.ReadExactlyAsync(length);
        byte[] payload = new byte[BinaryPrimitives.ReadInt32BigEndian(length)];
        await stream.ReadExactlyAsync(payload);
        using var json = JsonDocument.Parse(Encoding.UTF8.GetString(payload));
        var root = json.RootElement;
        return (
            root.GetProperty("SessionId").GetString()!,
            root.GetProperty("Role").GetString()!,
            root.GetProperty("Index").GetInt32());
    }
}
