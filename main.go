package main

import (

  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/proxy-divert"

  "path/filepath"
  "log"
  "fmt"
  "time"
  "bytes"
  "runtime"
  "os"
  "io"
  "crypto/tls"
  "encoding/hex"
  "sync"
  "net/http"

  "golang.org/x/net/ipv4"
  "golang.org/x/net/http2"

  "github.com/ilyaigpetrov/parse-tcp-go"
  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/at-fire"
)

var errlog = log.New(os.Stderr,
    "ERROR: ",
    log.Lshortfile)

var infolog = log.New(os.Stdout,
    "", log.Lshortfile)

// TLS SNIFFER

type proxyConn struct {
  tls.Conn
}

func (w *proxyConn) Read(b []byte) (n int, err error) {
  n, err = w.Conn.Read(b)
  infolog.Println("READ:", string(b))
  return
}

func (w *proxyConn) Write(b []byte) (n int, err error) {
  n, err = w.Conn.Write(b)
  infolog.Println("WRITE:", string(b))
  return
}


var serverConnection *http2.ClientConn
var proxyServer string

// SAFE BUFFER

type SafeBuffer struct {
    b bytes.Buffer
    m sync.Mutex
}
func (b *SafeBuffer) Read(p []byte) (n int, err error) {
    b.m.Lock()
    defer b.m.Unlock()
    return b.b.Read(p)
}
func (b *SafeBuffer) Write(p []byte) (n int, err error) {
    b.m.Lock()
    defer b.m.Unlock()
    return b.b.Write(p)
}
func (b *SafeBuffer) String() string {
    b.m.Lock()
    defer b.m.Unlock()
    return b.b.String()
}

var bufferToProxy *SafeBuffer

var isDisconnected = make(chan struct{})
var isConnected = make(chan struct{}, 1)

var injectPacket func([]byte) error

func keepHandlingReply(body io.ReadCloser) {

  defer body.Close()
  for {
    buf := make([]byte, 0, 65535) // big buffer
    tmp := make([]byte, 4096)     // using small tmp buffer for demonstrating
    for {
      log.Println("Reading body cycle")
      n, err := body.Read(tmp)
      if err != nil {
        if err != io.EOF {
          infolog.Println("read error:", err)
          isDisconnected <- struct{}{}
          <-isConnected
        }
        infolog.Println("EOF")
        fmt.Println(hex.Dump(buf))
        return
      }
      buf = append(buf, tmp[:n]...)

      header, err := ipv4.ParseHeader(buf)
      if err != nil {
        infolog.Println("Couldn't parse packet, dropping connnection.")
        return
      }
      if header.TotalLen == 0 && len(buf) > 0 {
        errlog.Println("Buffer is not parserable!")
        os.Exit(1)
      }
      if (header.TotalLen > len(buf)) {
        infolog.Printf("Reading more up to %d\n", header.TotalLen)
        //infolog.Println("CURRENT:", hex.Dump(buf))
        continue
      }
      packetData := buf[0:header.TotalLen]
      infolog.Println("INJECTING")

      packet, err := parseTCP.ParseTCPPacket(packetData)
      if err != nil {
        fmt.Println(hex.Dump(packetData))
        errlog.Fatal(err)
      }
      packet.Print(100)

      injectPacket(packetData)

      buf = buf[header.TotalLen:]
    }
  }

}

func connectTo(serverPoint string) (ifConnected bool) {

  cfg := new(tls.Config)
  cfg.NextProtos = append([]string{"h2"}, cfg.NextProtos...)

  front := "www.google.com:443"

  tlsConn, err := tls.Dial("tcp", front, cfg)
  if err != nil {
    errlog.Fatal(err)
  }
  sniffedTls := tlsConn //&proxyConn{*tlsConn}

  transport := &http2.Transport{}
  serverConnection, err = transport.NewClientConn(sniffedTls)
  if err != nil {
    errlog.Fatal(err)
  }

  bufferToProxy = &SafeBuffer{}

  userSecret := "super-random-key"

  req, err := http.NewRequest("POST", "/iptables?user-secret=" + userSecret, bufferToProxy)
  if err != nil {
    infolog.Println(err)
    return
  }
  req.Host = proxyServer
  req.Proto = "HTTP/2"
  req.URL.Scheme = "https"

  infolog.Printf("Proxy server is !%s!", proxyServer)
  fmt.Printf("REQ: %v + %s\n", req, req.Host)
  resp, err := serverConnection.RoundTrip(req)
  if err != nil {
    errlog.Println(err)
    return
  }
  go keepHandlingReply(resp.Body)
  isConnected <- struct{}{}
  return true

}

func keepConnectedTo(serverPoint string) {

  if connectTo(serverPoint) == false {
    errlog.Fatal("Failed to stick to this server.")
  }
  <-isConnected
  for _ = range isDisconnected {
    for {
      ok := connectTo(serverPoint)
      if ok {
        break
      }
      infolog.Println("Reconnect in 5 seconds")
      time.Sleep(time.Second * 5)
    }
  }

}

func packetHandler(packetData []byte) {

  packet, err := parseTCP.ParseTCPPacket(packetData)
  if err != nil {
    errlog.Println(err)
    return
  }
  infolog.Printf("SENDING TO PROXY:")
  packet.Print(100)

  _, err = bufferToProxy.Write(packetData)
  if err != nil {
    errlog.Println(err)
    isDisconnected <- struct{}{}
  }

}


func main() {

  if runtime.GOOS != "windows" {
    if os.Geteuid() != 0 {
      errlog.Fatal("This program requires admin privileges.")
    }
  }

  if len(os.Args) != 2 {
    infolog.Printf("Usage: %s example.appspot.com\n", filepath.Base(os.Args[0]))
    os.Exit(1)
  }

  proxyServer = os.Args[1]

  var unsub func() error
  var err error
  unsub, injectPacket, err = proxyDivert.SubscribeToPacketsExcept([]string{proxyServer + ":443"}, packetHandler)
  defer unsub()
  if err != nil {
    errlog.Fatal(err)
    return
  }

  go keepConnectedTo(proxyServer)

  infolog.Println("Traffic diverted.")

  exitChan := atFire.GetFireSignalsChannel()
  <-exitChan
  // all deffereds executed here

}
