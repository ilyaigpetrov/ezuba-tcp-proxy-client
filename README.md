# Ezuba TCP Proxy Client

Platforms: Linux, Windows  
Proxy server: https://github.com/ilyaigpetrov/ezuba-tcp-proxy-server

## Status

Barely proxies http sites, code is not perfect.  
Next step: pass data via channel domain fronted by google, currently data is passed via direct tcp to server.

## How To Develop

1. `go run ./cmd/download-dll.go` will download [WinDivert] dlls for Windows
2. `go build`
3. `sudo ./ezuba-tcp-proxy-client ezuba_server_ip:port`

[WinDivert]: https://reqrypt.org/windivert.html

## Why The Name?

Ezuba is abuze backwards.
