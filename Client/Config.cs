using System.Text.Json;
using System.Text.Json.Serialization;

public class VirtualIPConfig
{
    public string ServerIp { get; set; } = "192.168.192.1";

    public int ServerPort { get; set; } = 12345;

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
}
