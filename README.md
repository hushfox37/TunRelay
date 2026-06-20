# TunRelay

TunRelay is a simple TCP/TLS based TUN IP tunneling tool.

It runs a Windows or Linux client and a Linux server with NFQUEUE/iptables.
The server forwards selected TCP/UDP service ports to the client through an
encrypted tunnel.

## Features

- TLS encrypted client/server tunnel
- HMAC-SHA256 client authentication
- Windows client based on Wintun
- Linux client based on `/dev/net/tun`
- Linux server based on `iptables` and `libnetfilter_queue`
- Separate TCP and UDP service port configuration
- Automatic client TUN IP and port configuration delivery
- Batched data channel with runtime tunnel statistics
- Configurable console log level

## Repository Layout

```text
Client/   Windows/Linux client
Server/   Linux server
licenses/ Third-party license texts
```

## Requirements

### Client

- Windows x64 or Linux x64
- .NET 10 SDK or runtime
- Administrator/root privileges
- Windows: `wintun.dll` next to the client executable
- Linux: `/dev/net/tun` and the `ip` command from `iproute2`

### Server

- Linux
- .NET 10 SDK or runtime
- Root privileges
- `iptables`
- `libnetfilter_queue`

Example Debian/Ubuntu dependencies:

```bash
sudo apt install iptables libnetfilter-queue1
```

## Build

```bash
dotnet build Client/TunRelayClient.csproj
dotnet build Server/TunRelayServer.csproj
```

On Windows PowerShell:

```powershell
dotnet build Client\TunRelayClient.csproj
dotnet build Server\TunRelayServer.csproj
```

## Configuration

Both programs read `config.json` from their current working directory. If the
file does not exist, it is created with default values.

### Server `config.json`

```json
{
  "ServerIP": "203.0.113.10",
  "ListenPort": 19192,
  "TunIp": "10.0.0.2",
  "TcpPorts": [19191],
  "UdpPorts": [],
  "ClientID": "client-id-from-client-config",
  "Secret": "shared-secret",
  "LogLevel": "Information",
  "BatchDelayMs": 1,
  "MaxBatchBytes": 65536,
  "MaxBatchPackets": 32
}
```

Fields:

- `ServerIP`: server address used in the generated TLS certificate
- `ListenPort`: tunnel listening port
- `TunIp`: TUN IP assigned to the client
- `TcpPorts`: TCP service ports forwarded to the client
- `UdpPorts`: UDP service ports forwarded to the client
- `ClientID`: client identifier allowed to authenticate
- `Secret`: shared HMAC secret
- `LogLevel`: minimum console log level, for example `Information` or `Trace`
- `BatchDelayMs`: packet batching wait window in milliseconds
- `MaxBatchBytes`: maximum encoded packet bytes per batch
- `MaxBatchPackets`: maximum packets per batch

If `Secret` is empty, the server generates one and writes it to `config.json`,
then exits. Copy that value to the client config.

### Client `config.json`

```json
{
  "ServerIp": "203.0.113.10",
  "ServerPort": 19192,
  "ClientID": "generated-client-id",
  "Secret": "shared-secret",
  "LogLevel": "Information",
  "BatchDelayMs": 1,
  "MaxBatchBytes": 65536,
  "MaxBatchPackets": 32
}
```

Fields:

- `ServerIp`: server address
- `ServerPort`: server tunnel port
- `ClientID`: generated automatically if empty
- `Secret`: shared HMAC secret from the server
- `LogLevel`: minimum console log level, for example `Information` or `Trace`
- `BatchDelayMs`: packet batching wait window in milliseconds
- `MaxBatchBytes`: maximum encoded packet bytes per batch
- `MaxBatchPackets`: maximum packets per batch

You can also update the client secret with:

```powershell
TunRelayClient.exe --Secret "shared-secret"
```

### Batch tuning

Batch settings must be configured on both the client and server. Values are
normalized at startup:

- `BatchDelayMs`: `0` to `3`
- `MaxBatchBytes`: `4096` to `262144`
- `MaxBatchPackets`: `1` to `128`

The default values are conservative:

```json
{
  "BatchDelayMs": 1,
  "MaxBatchBytes": 65536,
  "MaxBatchPackets": 32
}
```

For throughput testing on high-latency public networks, start with:

```json
{
  "BatchDelayMs": 0,
  "MaxBatchBytes": 262144,
  "MaxBatchPackets": 128
}
```

If latency-sensitive traffic becomes less responsive, restore `BatchDelayMs` to
`1` or lower `MaxBatchPackets`.

## Run

Start the server as root:

```bash
sudo dotnet run --project Server/TunRelayServer.csproj
```

Start the Windows client as Administrator:

```powershell
dotnet run --project Client\TunRelayClient.csproj
```

Start the Linux client as root:

```bash
sudo dotnet run --project Client/TunRelayClient.csproj
```

For published binaries, run each executable from the directory containing its
`config.json`.

## Runtime Stats

When standard input is interactive, both programs provide a small console shell:

```text
stats
stats reset
help
```

Use `stats reset` on both sides before a benchmark so the displayed throughput
matches the test interval. Watch `channelDrops`, `protocolErrors`, and
`sinkWriteFailures`; they should remain `0` during a healthy run.

## Notes

- The server adds iptables rules while running and removes them on shutdown.
- Stop the server with `Ctrl+C` when possible so cleanup handlers can run.
- The Windows client creates a Wintun adapter and configures the TUN IP assigned
  by the server.
- The Linux client creates a TUN device named `Tunnel` and configures the TUN IP
  assigned by the server.
- This project does not distribute Linux `iptables` or `libnetfilter_queue`;
  they must be installed on the target system.

## License

This project is licensed under the Apache License 2.0. See `LICENSE`.

Third-party notices are listed in `THIRD-PARTY-NOTICES.md`.
