using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

public class TunRelayConfig
{
    public string ServerIP { get; set; } = "";
    public int ListenPort { get; set; } = 19192;
    public string TunIp { get; set; } = "";
    public int[] TcpPorts { get; set; } = { 19191 };
    public int[] UdpPorts { get; set; } = Array.Empty<int>();
    public string ClientID { get; set; } = "";
    public string Secret { get; set; } = "";
    public string Protocol { get; set; } = "tls";
    [JsonIgnore]
    public bool AutoCredentials { get; set; }
    public string LogLevel { get; set; } = "Information";

    // 数据通道微批处理参数(运行时会做边界归一化)
    public int BatchDelayMs { get; set; } = 1;
    public int MaxBatchBytes { get; set; } = 65536;
    public int MaxBatchPackets { get; set; } = 32;

    // 多连接并行: 上行(client->server)/下行(server->client)各自的数据连接数(运行时 clamp 到 1..16)。
    // 服务端单边权威,握手时下发给客户端。
    public int UplinkConnections { get; set; } = 4;
    public int DownlinkConnections { get; set; } = 4;
}

public static class ConfigManager
{
    public static TunRelayConfig LoadOrCreate(string path)
        => LoadOrCreate(path, TunRelayServer.TunRelayJsonContext.Default.TunRelayConfig);

    public static void Save(string path, TunRelayConfig config)
        => Save(path, config, TunRelayServer.TunRelayJsonContext.Default.TunRelayConfig);

    public static T LoadOrCreate<T>(string path, JsonTypeInfo<T> jsonTypeInfo) where T : new()
    {
        if (File.Exists(path))
        {
            string json = File.ReadAllText(path);
            return JsonSerializer.Deserialize(json, jsonTypeInfo) ?? new T();
        }

        T config = new();
        File.WriteAllText(path, JsonSerializer.Serialize(config, jsonTypeInfo));
        return config;
    }

    public static void Save<T>(string path, T config, JsonTypeInfo<T> jsonTypeInfo)
    {
        File.WriteAllText(path, JsonSerializer.Serialize(config, jsonTypeInfo));
    }

    public static T Update<T>(string path, Action<T> update, JsonTypeInfo<T> jsonTypeInfo) where T : new()
    {
        T config = LoadOrCreate(path, jsonTypeInfo);
        update(config);
        Save(path, config, jsonTypeInfo);
        return config;
    }
}

namespace TunRelayServer
{
    sealed class ServerConfigPayload
    {
        public string TunnelIP { get; set; } = "";
        public int[] Ports { get; set; } = Array.Empty<int>();
        public int[] TcpPorts { get; set; } = Array.Empty<int>();
        public int[] UdpPorts { get; set; } = Array.Empty<int>();
        public int UplinkConnections { get; set; }
        public int DownlinkConnections { get; set; }
        public string SessionId { get; set; } = "";
        public string Protocol { get; set; } = "tls";
    }

    sealed class AuthenticationRequest
    {
        public string ClientID { get; set; } = "";
        public long Timestamp { get; set; }
        public string Sign { get; set; } = "";
        public string[] SupportedProtocols { get; set; } = Array.Empty<string>();
    }

    sealed class CredentialProvisioningRequest
    {
        public string Mode { get; set; } = "";
        public string ClientID { get; set; } = "";
        public string[] SupportedProtocols { get; set; } = Array.Empty<string>();
    }

    sealed class CredentialProvisioningResponse
    {
        public string Status { get; set; } = "";
        public string Secret { get; set; } = "";
        public string Error { get; set; } = "";
    }

    [JsonSerializable(typeof(TunRelayConfig))]
    [JsonSerializable(typeof(ServerConfigPayload))]
    [JsonSerializable(typeof(DataChannelHandshake))]
    [JsonSerializable(typeof(AuthenticationRequest))]
    [JsonSerializable(typeof(CredentialProvisioningRequest))]
    [JsonSerializable(typeof(CredentialProvisioningResponse))]
    [JsonSourceGenerationOptions(WriteIndented = true)]
    partial class TunRelayJsonContext : JsonSerializerContext
    {
    }
}
