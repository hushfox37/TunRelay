using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

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
    public int ReconnectDelayMs { get; set; } = 5000;
    public int MaxReconnectAttempts { get; set; } = 0;

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? ServerPorts { get; set; }

    [JsonIgnore]
    public int EffectiveServerPort => ServerPorts ?? ServerPort;
}

public static class ConfigManager
{
    public static TunRelayConfig LoadOrCreate(string path)
        => LoadOrCreate(path, TunRelayJsonContext.Default.TunRelayConfig);

    public static void Save(string path, TunRelayConfig config)
        => Save(path, config, TunRelayJsonContext.Default.TunRelayConfig);

    public static TunRelayConfig Update(string path, Action<TunRelayConfig> update)
        => Update(path, update, TunRelayJsonContext.Default.TunRelayConfig);

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

public sealed class DataChannelHandshake
{
    public string SessionId { get; set; } = "";
    public string Role { get; set; } = "";
    public int Index { get; set; }
}

public sealed class AuthenticationRequest
{
    public string ClientID { get; set; } = "";
    public long Timestamp { get; set; }
    public string Sign { get; set; } = "";
}

public sealed class CredentialProvisioningRequest
{
    public string Mode { get; set; } = "";
    public string ClientID { get; set; } = "";
}

public sealed class CredentialProvisioningResponse
{
    public string Status { get; set; } = "";
    public string Secret { get; set; } = "";
}

[JsonSerializable(typeof(TunRelayConfig))]
[JsonSerializable(typeof(DataChannelHandshake))]
[JsonSerializable(typeof(AuthenticationRequest))]
[JsonSerializable(typeof(CredentialProvisioningRequest))]
[JsonSerializable(typeof(CredentialProvisioningResponse))]
[JsonSourceGenerationOptions(WriteIndented = true)]
public partial class TunRelayJsonContext : JsonSerializerContext
{
}
