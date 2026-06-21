using System.Text.Json;
using System.Text.Json.Serialization;

public class TunRelayConfig
{
    public string ServerIp { get; set; } = "";

    public int ServerPort { get; set; } = 12345;

    public string ClientID { get; set; } = "";

    public string Secret { get; set; } = "";
    public string LogLevel { get; set; } = "Information";

    // 数据通道微批处理参数(运行时会做边界归一化)
    public int BatchDelayMs { get; set; } = 1;
    public int MaxBatchBytes { get; set; } = 65536;
    public int MaxBatchPackets { get; set; } = 32;

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? ServerPorts { get; set; }

    [JsonIgnore]
    public int EffectiveServerPort => ServerPorts ?? ServerPort;
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
