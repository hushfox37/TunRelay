using System.Text.Json;

public class VirtualIPConfig
{
    public string ServerIP { get; set; } = "";
    public int ListenPort { get; set; } = 19192;
    public string VirtualIp { get; set; } = "";
    public int[] TcpPorts { get; set; } = { 19191 };
    public int[] UdpPorts { get; set; } = Array.Empty<int>();
    public string ClientID { get; set; } = "";
    public string Secret { get; set; } = "";
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
