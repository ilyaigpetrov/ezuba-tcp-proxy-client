package main

import (

  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/proxy-divert"
  "golang.org/x/net/ipv4"
  "path/filepath"
  "fmt"
  "log"
  "time"
  "bytes"
  "runtime"
  "os"
  "io"
  "encoding/hex"
  "net"
  "os/signal"

  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/nettools"
)

var errlog = log.New(os.Stderr,
    "ERROR: ",
    log.Lshortfile)

var Info = log.New(os.Stdout,
    "INFO: ",
    log.Ldate|log.Ltime|log.Lshortfile)

func xor42(data []byte) []byte {
  for i, b := range data {
    data[i] = b ^ 42
  }
  return data
}

var remote net.Conn
var isDisconnected = make(chan struct{})
var isConnected = make(chan struct{}, 1)

var injectPacket func([]byte) error

func keepHandlingReply() {

  for {
    buf := make([]byte, 0, 65535) // big buffer
    tmp := make([]byte, 4096)     // using small tmp buffer for demonstrating
    for {
      n, err := remote.Read(tmp)
      if err != nil {
        if err != io.EOF {
          fmt.Println("read error:", err)
          isDisconnected <- struct{}{}
          <-isConnected
        }
        break
      }
      xor42(tmp)
      buf = append(buf, tmp[:n]...)
      fmt.Println("RECEIVED:", hex.EncodeToString(buf))

      header, err := ipv4.ParseHeader(buf)
      if err != nil {
        fmt.Println("Couldn't parse packet, dropping connnection.")
        break
      }
      if header.TotalLen == 0 && len(buf) > 0 {
        fmt.Println("Buffer is not parserable!")
        os.Exit(1)
      }
      if (header.TotalLen > len(buf)) {
        fmt.Printf("Reading more up to %d\n", header.TotalLen)
        continue
      }
      packetData := buf[0:header.TotalLen]
      fmt.Println("Injecting packet...")


      fmt.Println(hex.EncodeToString(packetData))

      _, ip, tcp, _, err := nettools.ParseTCPPacket(packetData)
      if err != nil {
        panic(err)
      }
      fmt.Printf("Receiving from %s:%d to %s:%d\n", ip.SrcIP.String(), tcp.SrcPort, ip.DstIP.String(), tcp.DstPort)

      fmt.Println(hex.Dump(packetData))

      injectPacket(packetData)

      buf = buf[header.TotalLen:]
    }
  }

}

func connectTo(serverPoint string) (ifConnected bool) {

  fmt.Printf("Dialing %s\n...", serverPoint)
  var err error
  if remote != nil {
    remote.Close()
    remote = nil
  }
  fmt.Println("REMOTE REDEFINED")
  remote, err = net.Dial("tcp", serverPoint)
  if err != nil {
    fmt.Println("Can't connect to the server!")
    return false
  }
  fmt.Println("Connected!")
  isConnected <- struct{}{}
  return true

}

func keepConnectedTo(serverPoint string) {

  if connectTo(serverPoint) == false {
    errlog.Fatal("Failed to stick to this server.")
  }
  <-isConnected
  go keepHandlingReply()
  for _ = range isDisconnected {
    for {
      ok := connectTo(serverPoint)
      if ok {
        break
      }
      fmt.Println("Reconnect in 5 seconds")
      time.Sleep(time.Second * 5)
    }
  }

}

func packetHandler(packetData []byte) {
  if remote == nil {
    return
  }

  _, ip, tcp, _, err := nettools.ParseTCPPacket(packetData)
  if err != nil {
    errlog.Println(err)
    return
  }
  fmt.Printf("Sending from %s:%d to %s:%d\n", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)

  _, err = io.Copy(remote, bytes.NewReader(packetData))
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
    fmt.Printf("Usage: %s proxy_address:port\n", filepath.Base(os.Args[0]))
    os.Exit(1)
  }

  serverAddr := os.Args[1]

  var unsub func() error
  var err error
  unsub, injectPacket, err = proxyDivert.SubscribeToPacketsExcept([]string{serverAddr}, packetHandler)
  if err != nil {
    errlog.Fatal(err)
  }
  defer unsub()

  go keepConnectedTo(serverAddr)

  fmt.Println("Traffic diverted.")

  controlC := make(chan os.Signal)
  signal.Notify(controlC, os.Interrupt)
  go func(){
    <-controlC
    unsub()
    Info.Println("Exiting after Ctrl+C")
    os.Exit(0)
  }()
  select{}

}
