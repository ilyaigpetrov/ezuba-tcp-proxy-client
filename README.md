# Ezuba TCP Proxy Client

Platforms: Linux, Windows

## How To Develop It

1. `go run ./cmd/download-dll.go` will download [WinDivert] dlls for Windows
2. `go build`
3. `sudo ./ezuba-tcp-proxy-client ezuba_server_ip:port`

[WinDivert]: https://reqrypt.org/windivert.html
