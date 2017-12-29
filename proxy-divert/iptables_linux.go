package proxyDivert

import (
  "net"
  "log"
  "math"
  "os"
  "fmt"
  //"golang.org/x/net/ipv4"
  "github.com/coreos/go-iptables/iptables"
  "syscall"
  //"errors"
  //"encoding/hex"
  //"time"
  "strings"
  "strconv"

  "github.com/google/gopacket/layers"

  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/nettools"
  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/at-fire"

  "gopkg.in/oleiade/reflections.v1"
)

var errlog = log.New(os.Stderr,
    "ERROR: ",
    log.Lshortfile)

var outlog = log.New(os.Stdout,
    "INFO: ", 0)

type realAddr struct {
  realIP string
  realPort uint16
  sourceIP string
  sourcePort uint16
  iptConnection *net.TCPConn
}

var PORT_TO_DST = make(map[uint16]realAddr)
var PORT_TO_SYN = make(map[uint16][]byte)

var noop = func() {}

func sendViaSocket(packetData []byte, toIP net.IP, port int) error {

  s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
  if err != nil {
    return err
  }
  defer syscall.Close(s)

  var arr [4]byte
  copy(arr[:], toIP.To4()[:4])
  addr := syscall.SockaddrInet4{
    Addr: arr,
    Port: port,
  }
  return syscall.Sendto(s, packetData, 0, &addr)

}

func SubscribeToPacketsExcept(exceptions []string, packetHandler func([]byte)) (unsub func() error, injectPacket func([]byte) error, err error) {

  internalIP := "127.0.0.5"
  port := 2222

  ipConn, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: net.ParseIP(internalIP)})
  if err != nil {
    fmt.Println("Try running under root rights.")
    errlog.Fatal(err)
  }

  log.Println("Listening!")
  maxIPPacketSize := math.MaxUint16

  go func(){
    for {
      ipBuf := make([]byte, maxIPPacketSize)
      oob := make([]byte, maxIPPacketSize)
      n, _, _, _, err := ipConn.ReadMsgIP(ipBuf, oob)
      if err != nil {
        errlog.Println(err)
      }
      packetData := ipBuf[:n]

      _, ip, tcp, recompile, err := nettools.ParseTCPPacket(packetData)
      if err != nil {
        errlog.Println(err)
        continue
      }

      dst := ip.DstIP.String()
      src := ip.SrcIP.String()

      if dst != internalIP {
        fmt.Printf("%s not internal %s\n", dst, internalIP)
        continue
      }

      fmt.Printf("Internal: Packet from %s:%d to %s:%d %d", ip.SrcIP.String(), tcp.SrcPort, ip.DstIP.String(), tcp.DstPort, tcp.Seq)
      flags := strings.Split("FIN SYN RST PSH ACK URG ECE CWR NS", " ")
      for _, flag := range flags {
        val, err := reflections.GetField(tcp, flag)
        if err != nil {
          errlog.Println(err, "REFLECT ERROR!")
        }
        if val.(bool) {
          fmt.Printf(" %s", flag)
        }
      }
      fmt.Printf("\n")

      rly, ok := PORT_TO_DST[uint16(tcp.DstPort)]
      if !ok {
        fmt.Println("NOT ACCEPTED YET")
        if tcp.SYN {
          PORT_TO_SYN[uint16(tcp.DstPort)] = packetData
        } else {
          fmt.Printf("%s:%d not in ports\n", dst, tcp.DstPort)
          //os.Exit(1)
        }
        continue
      }

      rlyStr := rly.realIP
      rlyPort := rly.realPort
      rlyIP := net.ParseIP(rlyStr)

      if (ip.SrcIP.Equal(rlyIP)) {
        // It's reply from target, inbound packet
        // Already injected.
        continue
      } else {
        ip.DstIP = rlyIP
        tcp.DstPort = layers.TCPPort(rlyPort)
      }

      src = fmt.Sprintf("%s:%d", ip.SrcIP.String(), tcp.SrcPort)
      dst = fmt.Sprintf("%s:%d", ip.DstIP.String(), tcp.DstPort)
      fmt.Printf("From %s to %s\n", src, dst)

      modPacket, err := recompile()
      if err != nil {
        errlog.Println(err)
        continue
      }

      packetHandler(modPacket)

    }
  }()

  listener, err := net.ListenTCP("tcp", &net.TCPAddr{ IP: net.ParseIP(internalIP), Port: port })
  if err != nil {
    errlog.Fatal(err)
  }
  go func(){

    // Handle incoming iptConnections on listener
    for {
      iptConnection, err := listener.AcceptTCP()
      if iptConnection == nil || err != nil {
        errlog.Println("Nil iptConnection", err)
        continue
      }
      la := iptConnection.LocalAddr()
      if (la == nil) {
        iptConnection.Close()
        errlog.Println("Connection lost (no local addr)!")
        continue
      }
      remoteStr := iptConnection.RemoteAddr().String()
      fmt.Printf("Connection from %s to %s accepted\n", la.String(), remoteStr)

      go func(){

        defer iptConnection.Close()
        ipv4, port, newConn, err := getOriginalDst(iptConnection)
        // fmt.Println( la.String(), fmt.Sprintf("%s:%d", ipv4, port) )

        iptConnection = newConn
        if err != nil {
          errlog.Println(err)
          return
        }

        parts := strings.Split(remoteStr, ":")
        sourceIP := parts[0]
        sourcePort, err := strconv.Atoi(parts[1])
        if err != nil {
          return
        }

        PORT_TO_DST[uint16(sourcePort)] = realAddr{
          realIP: ipv4,
          realPort: port,
          sourceIP: sourceIP,
          sourcePort: uint16(sourcePort),
          iptConnection: iptConnection,
        }

      }()
    }

  }()

  injectPacket = func(packetData []byte) error {

    _, ip, tcp, recompile, err := nettools.ParseTCPPacket(packetData)
    if err != nil {
      return err
    }

    rly, ok := PORT_TO_DST[uint16(tcp.DstPort)]
    if !ok {
      fmt.Printf("%s:%d not in ports\n", ip.DstIP.String(), tcp.DstPort)
      os.Exit(1)
    }

    ip.DstIP = net.ParseIP(rly.sourceIP)
    tcp.DstPort = layers.TCPPort(rly.sourcePort)

    ip.SrcIP = net.ParseIP("127.0.0.1")
    tcp.SrcPort = layers.TCPPort(port)

    packetData, err = recompile()
    if err != nil {
      errlog.Println(err)
      return err
    }

    src := fmt.Sprintf("%s:%d", ip.SrcIP.String(), tcp.SrcPort)
    dst := fmt.Sprintf("%s:%d", ip.DstIP.String(), tcp.DstPort)
    fmt.Printf("INJECT: From %s to %s\n", src, dst)

    if len(tcp.Payload) > 0 {
      _, err = rly.iptConnection.Write(tcp.Payload)
      if err != nil {
        errlog.Println(err)
      }
    } else {
      err = sendViaSocket(packetData, ip.DstIP, int(tcp.DstPort))
      if err != nil {
        errlog.Println(err)
        return err
      }
    }

    return nil

  }

  appendRule := func(table, chain string, args ...string) (func() error, error) {

    ipt, err := iptables.New()
    if err != nil {
      return nil, err
    }
    err = ipt.AppendUnique(table, chain, args...)
    if err != nil {
      return nil, err
    }
    return func() error {

      fmt.Println("Restoring Internet settings!")
      return ipt.Delete(table, chain, args...)

    }, nil

  }

  negs := []string{}
  if len(exceptions) > 0 {
    ipsports, err := hostsToIPs(exceptions)
    if err != nil {
      return nil, nil, err
    }
    ip := ipsports[0].ips[0]
    negs = []string{"!", "-d", ip}
    fmt.Println("NEGS", negs)
  }

  args := []string{"-p", "tcp", "-m", "tcp", "-j", "DNAT", "--dport", "80", "--to-destination", "127.0.0.5:2222"}
  args = append(args, negs...)
  unsub, err = appendRule("nat", "OUTPUT", args...)
  if err != nil {
    return nil, nil, err
  }

  fire := atFire.GetFireSignalsChannel()
  go func(){
    for _ = range fire {
      unsub()
      fmt.Println("Exiting after signal.")
    }
  }()

  return unsub, injectPacket, nil

}


