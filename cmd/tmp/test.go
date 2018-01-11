package main

import (
  "golang.org/x/net/http2"
  "net/http"
  "fmt"
  "time"
  "io/ioutil"
  "crypto/x509"
  "crypto/tls"
)

func main() {

  rootPEM := `-----BEGIN CERTIFICATE-----
MIIEHzCCAwegAwIBAgIJAJx91ukoeHAaMA0GCSqGSIb3DQEBCwUAMIGlMQswCQYD
VQQGEwJSVTEeMBwGA1UECAwVU3ZlcmRsb3Zza2F5YSBPYmxhc3QnMRMwEQYDVQQH
DApTdWtob3kgTG9nMRYwFAYDVQQKDA1BbnRpY2Vuc29yaXR5MQ4wDAYDVQQLDAVo
b3VzZTESMBAGA1UEAwwJbG9jYWxob3N0MSUwIwYJKoZIhvcNAQkBFhZpbHlhaWdw
ZXRyb3ZAZ21haWwuY29tMB4XDTE4MDExMDE2MTQzM1oXDTI4MDEwODE2MTQzM1ow
gaUxCzAJBgNVBAYTAlJVMR4wHAYDVQQIDBVTdmVyZGxvdnNrYXlhIE9ibGFzdCcx
EzARBgNVBAcMClN1a2hveSBMb2cxFjAUBgNVBAoMDUFudGljZW5zb3JpdHkxDjAM
BgNVBAsMBWhvdXNlMRIwEAYDVQQDDAlsb2NhbGhvc3QxJTAjBgkqhkiG9w0BCQEW
FmlseWFpZ3BldHJvdkBnbWFpbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDA3FkikbZm1Ydb88crBm31VmAg2PGNfOtNmlPlqoq5kLLcHTgcMjdL
2gZTW9EwArmEEhNiheiwfur6bpDFY+dNcFWfuDk5d+EyRGHZmUdCszp8Lyk4elZ3
qUJ9kKhjBTNEht+kJvyrcfB9FdnCmxLkY2ahIlrqTOLoBfZkCpiG7kJIcfhRoPWy
5KzxuHtvVTIaTH//d9Xr4GV+tcdtszJiAaKhRCcKbp48tnxBi01+cbBCDyOLZPvI
QFV4RiecYu6ZFZB1Tv6awVMN32L7n3Qt5e6lO1tdO1shwneuOo8SwlRT63Go7hKv
F2vFXLdLXkh8SaLGVAtJFXZ5eIAK+pSpAgMBAAGjUDBOMB0GA1UdDgQWBBQKewyj
yYDdIvbgfqA8GloZ7GnQ2TAfBgNVHSMEGDAWgBQKewyjyYDdIvbgfqA8GloZ7GnQ
2TAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBHspIMeNn8kbjrTSFb
eER/0O69TsfU5RDYXfgx0LdqQLL/MftD+GxPmAVi6pO8RzJphFfB/TS6jH2h8YrK
CfOwctufy+kEqwtxv3YhNfVOv981RT7gaDYYqeWreI29M0sqIQmY+9Jy7W+hROTq
XIn/E3vtX2PJGNBogZZagP1GywJAxuq+IgxejVb4xMHnNu0mckw+jNsUw0WHI249
xKtv4a3ZSdD7k10rNJ1hYWOPeItB2YdGVlX1Sq+5KdjvbNRbYd0iSpCiTJPXWsZr
R9UubsdHvvRE90RVOrB2wcHaFWryQN+VC/Xg8HaieYojgDIZc5ALsn7z4s1LnQwB
qi/a
-----END CERTIFICATE-----`

  roots := x509.NewCertPool()
  ok := roots.AppendCertsFromPEM([]byte(rootPEM))
  if !ok {
    panic("failed to parse root certificate")
  }
  tlsConf := &tls.Config{RootCAs: roots}
  conn, err := tls.Dial("tcp", "www.google.com:443", tlsConf)
  if err != nil {
    panic(err)
  }

  tr := &http.Transport{
    MaxIdleConns:       10,
    IdleConnTimeout:    30 * time.Second,
    DisableCompression: true,
  }
  err = http2.ConfigureTransport(tr)
  if err != nil {
    panic(err)
  }
  /*
  cc, err := tr.NewClientConn(conn)
  if err != nil {
    panic(err)
  }
  */
  client := &http.Client{Transport: tr}
  /*
  req, err := http.NewRequest("PRI", "https://localhost/", nil)
  if err != nil {
    panic(err)
  }
  resp, err := client.Do(req)
  */
  target := "https://localhost"
  resp1, err := client.Get(target + "/1")
  if err != nil {
    panic(err)
  }
  resp2, err := client.Get(target + "/2")
  if err != nil {
    panic(err)
  }
  defer resp1.Body.Close()
  defer resp2.Body.Close()
  body, err := ioutil.ReadAll(resp1.Body)
  if err != nil {
    panic(err)
  }
  fmt.Println(string(body))

}
