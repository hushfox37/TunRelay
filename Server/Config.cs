using System.Text.Json;

public class VirtualIPConfig
{
    public string VirtualIp { get; set; } = "172.30.98.75";
    public int ListenPort { get; set; } = 12345;
    public int[] Ports { get; set; } = { 19191 };
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
