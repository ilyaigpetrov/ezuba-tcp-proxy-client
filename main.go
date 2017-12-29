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
  //"encoding/hex"
  "net"

  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/nettools"
  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/at-fire"

  "github.com/google/gopacket/pcapgo"
  "github.com/google/gopacket/layers"
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
      xor42(tmp[:n])
      buf = append(buf, tmp[:n]...)

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

      packet, _, _, _, err := nettools.ParseTCPPacket(packetData)
      if err != nil {
        panic(err)
      }

      fmt.Println("RECEIVE:")
      nettools.PrintPacket(packet)

      injectPacket(packetData)
      //pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

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

  packet, _, _, _, err := nettools.ParseTCPPacket(packetData)
  if err != nil {
    errlog.Println(err)
    return
  }
  fmt.Println("SENDING:")
  nettools.PrintPacket(packet)
  //pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())

  _, err = io.Copy(remote, bytes.NewReader(packetData))
  if err != nil {
    errlog.Println(err)
    isDisconnected <- struct{}{}
  }

}

var pcapWriter *pcapgo.Writer

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


  snapshotLen := uint32(65535)
  f, _ := os.Create("test.pcap")
  pcapWriter := pcapgo.NewWriter(f)
  pcapWriter.WriteFileHeader(snapshotLen, layers.LinkTypeIPv4)
  defer f.Close()

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

  exitChan := atFire.GetFireSignalsChannel()
  <-exitChan
  // all deffereds executed here

}
