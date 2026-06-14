# Third-Party Notices

This project is licensed under the Apache License 2.0. This file lists
third-party components and runtime dependencies used by the project.

## Distributed With This Project

### Wintun

- Component: `Client/wintun.dll`
- Copyright: WireGuard LLC
- Website: https://www.wintun.net/
- License: Wintun Prebuilt Binaries License
- License file: `licenses/WINTUN-PREBUILT-LICENSE.txt`

This project uses the prebuilt `wintun.dll` only through the Wintun API.
The Wintun binary must not be modified, reverse engineered, decompiled,
disassembled, or redistributed separately from software that uses it through
the permitted API.

### Newtonsoft.Json

- Package: `Newtonsoft.Json`
- Version: `13.0.4`
- Copyright: James Newton-King
- License: MIT
- Website: https://www.newtonsoft.com/json
- NuGet: https://www.nuget.org/packages/Newtonsoft.Json/13.0.4

## Runtime Dependencies Not Distributed With This Project

The Linux server requires the following components to be installed on the
target system. They are not distributed with this project.

- `iptables`
- `libnetfilter_queue.so.1`

## Removed / Not Used

`SharpDivert` is not used by the current code and has been removed from the
client project file.
