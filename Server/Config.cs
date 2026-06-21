using System.Text.Json;

public class TunRelayConfig
{
    public string ServerIP { get; set; } = "";
    public int ListenPort { get; set; } = 19192;
    public string TunIp { get; set; } = "";
    public int[] TcpPorts { get; set; } = { 19191 };
    public int[] UdpPorts { get; set; } = Array.Empty<int>();
    public string ClientID { get; set; } = "";
    public string Secret { get; set; } = "";
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
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true
    };

    public static T LoadOrCreate<T>(string path) where T : new()
    {
        if (File.Exists(path))
        {
            string json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<T>(json, Options) ?? new T();
        }

        T config = new();
        File.WriteAllText(path, JsonSerializer.Serialize(config, Options));
        return config;
    }

    public static void Save<T>(string path, T config)
    {
        File.WriteAllText(path, JsonSerializer.Serialize(config, Options));
    }

    public static T Update<T>(string path, Action<T> update) where T : new()
    {
        T config = LoadOrCreate<T>(path);
        update(config);
        Save(path, config);
        return config;
    }
}
