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
- Parallel data connections with stable per-flow routing
- Configurable console log level
- Windows/Linux x64/arm64 TUN support with runtime `epoll_event` layout detection

## Repository Layout

```text
Client/   Windows/Linux client
Server/   Linux server
licenses/ Third-party license texts
```

## Requirements

### Client

- Windows or Linux
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

Publish runtime-dependent binaries for a specific target runtime:

```bash
dotnet publish Client/TunRelayClient.csproj -c Release -r linux-x64 --self-contained false
dotnet publish Client/TunRelayClient.csproj -c Release -r linux-arm64 --self-contained false
dotnet publish Server/TunRelayServer.csproj -c Release -r linux-x64 --self-contained false
```

On Windows PowerShell:

```powershell
dotnet publish Client\TunRelayClient.csproj -c Release -r linux-x64 --self-contained false
dotnet publish Client\TunRelayClient.csproj -c Release -r linux-arm64 --self-contained false
dotnet publish Server\TunRelayServer.csproj -c Release -r linux-x64 --self-contained false
```

Published files are written under `bin/Release/net10.0/<runtime>/publish/`.

Publish self-contained single-file binaries when the target machine may not
have the matching .NET runtime installed:

```bash
dotnet publish Client/TunRelayClient.csproj -c Release -r linux-arm64 --self-contained true -p:PublishSingleFile=true -p:DebugType=none -p:DebugSymbols=false
dotnet publish Server/TunRelayServer.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -p:DebugType=none -p:DebugSymbols=false
```

On Windows PowerShell:

```powershell
dotnet publish Client\TunRelayClient.csproj -c Release -r linux-arm64 --self-contained true -p:PublishSingleFile=true -p:DebugType=none -p:DebugSymbols=false
dotnet publish Server\TunRelayServer.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -p:DebugType=none -p:DebugSymbols=false
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
  "MaxBatchPackets": 32,
  "UplinkConnections": 4,
  "DownlinkConnections": 4
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
- `UplinkConnections`: client-to-server data connection count
- `DownlinkConnections`: server-to-client data connection count

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
- `ServerPorts`: optional legacy alias for `ServerPort`; if present, it takes
  precedence over `ServerPort`
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

### Parallel connections

The server controls the number of data connections and sends those values to
the client during the control handshake. `UplinkConnections` and
`DownlinkConnections` are normalized to `1` through `16` at runtime.

Packets are assigned to a data connection with a stable IPv4 5-tuple flow hash
so packets from the same TCP/UDP flow stay on the same connection.

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
