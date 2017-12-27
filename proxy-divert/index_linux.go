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

  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"

  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/nettools"
  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/at-fire"
  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/proxy-divert/vendor-local/freeport"
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
  connection *net.TCPConn
}

var SRC_TO_DST = make(map[string]realAddr)
var PORT_TO_DST = make(map[uint16]realAddr)

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
  listener, err := net.ListenTCP("tcp", &net.TCPAddr{ IP: net.IPv4(127,0,0,1), Port: port })
  if err != nil {
    errlog.Fatal(err)
  }
  go func(){

    // Handle incoming connections on listener
    for {
      connection, err := listener.AcceptTCP()
      if connection == nil || err != nil {
        errlog.Println("Nil connection", err)
        continue
      }
      la := connection.LocalAddr()
      if (la == nil) {
        connection.Close()
        errlog.Println("Connection lost (no local addr)!")
        continue
      }
      remoteStr := connection.RemoteAddr().String()
      fmt.Printf("Connection from %s to %s accepted\n", la.String(), remoteStr)

      go func(){

        defer connection.Close()
        ipv4, port, newConn, err := getOriginalDst(connection)
        // fmt.Println( la.String(), fmt.Sprintf("%s:%d", ipv4, port) )

        connection = newConn
        if err != nil {
          errlog.Println(err)
          return
        }
        defer newConn.Close()

        freePortInt, err := freeport.GetFreePort(internalIP)
        freePort := uint16(freePortInt)
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

        SRC_TO_DST[remoteStr] = realAddr{
          realIP: ipv4,
          realPort: port,
          sourceIP: sourceIP,
          sourcePort: uint16(sourcePort),
          connection: connection,
        }
        PORT_TO_DST[freePort] = SRC_TO_DST[remoteStr]
        defer delete(SRC_TO_DST, remoteStr)
        defer delete(PORT_TO_DST, freePort)


        s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM , 0)
        if err != nil {
          errlog.Println(err)
          return
        }
        defer syscall.Close(s)

        var iip [4]byte
        copy(iip[:], net.ParseIP(internalIP).To4()[:4])
        addr := syscall.SockaddrInet4{
          Port: freePortInt,
          Addr: iip,
        }
        err = syscall.Bind(s, &addr)
        if err != nil {
          errlog.Println(err)
          return
        }
        err = syscall.Connect(s, &addr)
        if err != nil {
          errlog.Println(err)
          return
        }

        for {
          fmt.Println("NONBLOCK")
          conIn := make([]byte, 1000000) // about 1MB
          fmt.Println("READ FROM SYSTEM")
          n, err := connection.Read(conIn)
          if err != nil {
            errlog.Println(err)
            return
          }
          fmt.Println("WRITE TO SOCKET")
          _, err = syscall.Write(s, conIn[:n])
          if err != nil {
            errlog.Println(err)
            return
          }
        }

      }()
    }

  }()

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

      var dst string
      var src string
      // Decode a packet
      packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)
      // Get the TCP layer from this packet
      if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
        ip, _ := ipLayer.(*layers.IPv4)
        dst = ip.DstIP.String()
        src = ip.SrcIP.String()

        if dst != internalIP {
          fmt.Printf("%s not internal %s\n", dst, internalIP)
          continue
        }

        if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
          tcp, _ := tcpLayer.(*layers.TCP)

          fmt.Printf("Internal packet from %s:%d to %s:%d\n", ip.SrcIP.String(), tcp.SrcPort, ip.DstIP.String(), tcp.DstPort)

          rly, ok := PORT_TO_DST[uint16(tcp.DstPort)]
          if !ok {
            fmt.Printf("%s:%d not in ports\n", dst, tcp.DstPort)
            os.Exit(1)
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

          options := gopacket.SerializeOptions{
            ComputeChecksums: true,
            FixLengths: true,
          }
          newBuffer := gopacket.NewSerializeBuffer()
          tcp.SetNetworkLayerForChecksum(ip)
          err := gopacket.SerializePacket(newBuffer, options, packet)
          if err != nil {
            errlog.Println(err)
            continue
          }

          outgoingPacket := newBuffer.Bytes()
          _ = outgoingPacket
          packetHandler(outgoingPacket)

        }

      }

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
      _, err = rly.connection.Write(tcp.Payload)
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

  args := []string{"-p", "tcp", "-m", "tcp", "-j", "REDIRECT", "--dport", "80", "--to-port", "2222"}
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


