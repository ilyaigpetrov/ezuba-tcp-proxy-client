package proxyDivert

import (
  "net"
  "math"
  "os"
  "log"
  //"golang.org/x/net/ipv4"
  "github.com/coreos/go-iptables/iptables"
  "syscall"
  //"errors"
  //"encoding/hex"
  //"time"
  "strings"
  "strconv"

  "github.com/google/gopacket/layers"

  "github.com/ilyaigpetrov/parse-tcp-go"
  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/at-fire"

)

var errlog = log.New(os.Stderr,
    "ERROR: ",
    log.Lshortfile)

var infolog = log.New(os.Stdout,
    "", 0)

type realAddr struct {
  realIP string
  realPort uint16
  sourceIP string
  sourcePort uint16
  iptConnection *net.TCPConn
  initialSequence uint32
}

type TCPInits struct {
  synackSeq uint32
  seqDiff uint32
  syn []byte
  packetQueue [][]byte
}

var PORT_TO_DST = make(map[uint16]realAddr)
var PORT_TO_INITS = make(map[uint16]TCPInits)

func closeConnection(srcPort uint16) {

  rly := PORT_TO_DST[srcPort]
  if rly.iptConnection != nil {
    rly.iptConnection.Close()
  }
  delete(PORT_TO_DST, srcPort)
  delete(PORT_TO_INITS, srcPort)

}

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

  var processPacketData func([]byte)

  /*
  processSynAckFor := func(srcPort uint16) {

    synack, ok := PORT_TO_SYNACK[srcPort]
    if ok {
      delete(PORT_TO_SYNACK, srcPort)
      infolog.Println("Processing synack")
      for _, packet := range packets {
        processPacketData(packet)
      }
    } else {
      infolog.Printf("Queue is empty for %d\n", srcPort)
    }

  }
  */

  processPacketData = func(packetData []byte) {

    packet, err := parseTCP.ParseTCPPacket(packetData)
    if err != nil {
      errlog.Println(err)
      return
    }
    infolog.Println("RECEIVED RAW PACKET:")
    packet.Print(100)

    ip := packet.IP
    tcp := packet.TCP

    dstIP := ip.DstIP.String()
    srcIP := ip.SrcIP.String()

    if dstIP != internalIP {
      infolog.Printf("%s not internal %s\n", dstIP, internalIP)
      return
    }

    srcPort := uint16(tcp.SrcPort)

    if tcp.SYN && !tcp.FIN {
      _, ok := PORT_TO_INITS[srcPort]
      if !ok {
        PORT_TO_INITS[srcPort] = TCPInits{}
        inits := PORT_TO_INITS[srcPort]
        if tcp.ACK {
          inits.synackSeq = tcp.Seq
          infolog.Printf("Saved sequence number %d\n", tcp.Seq)
        } else {
          inits.syn = packetData
          infolog.Println("Saved SYN packet")
        }
        return
      }
    }

    infolog.Printf("Checking port %d\n", srcPort)
    rly, ok := PORT_TO_DST[srcPort]
    if !ok {
      infolog.Printf("%s:%d not in ports YET, queueing\n", srcIP, tcp.SrcPort)
      inits := PORT_TO_INITS[srcPort]
      inits.packetQueue = append(inits.packetQueue, packetData)
      return
    }

    // sendSynPacketFor(srcPort)

    rlyStr := rly.realIP
    rlyPort := rly.realPort
    rlyIP := net.ParseIP(rlyStr)

    if (ip.SrcIP.Equal(rlyIP)) {
      // It's reply from target, inbound packet.
      // Must be injected after reading from proxy connection.
      infolog.Println("This packet is an inbound reply, already handled.")
      return
    } else {
      ip.DstIP = rlyIP
      tcp.DstPort = layers.TCPPort(rlyPort)
    }

    //src := infolog.Sprintf("%s:%d", ip.SrcIP.String(), tcp.SrcPort)
    //dst := infolog.Sprintf("%s:%d", ip.DstIP.String(), tcp.DstPort)

    modPacket, err := packet.Recompile()
    if err != nil {
      errlog.Println(err)
      return
    }

    packetHandler(modPacket)

  }

  ipConn, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: net.ParseIP(internalIP)})
  if err != nil {
    infolog.Println("Try running under root rights.")
    errlog.Fatal(err)
  }

  infolog.Println("Listening!")
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

      processPacketData(packetData)

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
      infolog.Printf("Connection from %s to %s accepted\n", la.String(), remoteStr)

      go func(){

        defer iptConnection.Close()
        ipv4, port, newConn, err := getOriginalDst(iptConnection)
        // infolog.Println( la.String(), infolog.Sprintf("%s:%d", ipv4, port) )

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

        srcPort := uint16(sourcePort)

        PORT_TO_DST[uint16(sourcePort)] = realAddr{
          realIP: ipv4,
          realPort: port,
          sourceIP: sourceIP,
          sourcePort: srcPort,
          iptConnection: iptConnection,
        }
        infolog.Printf("Added source port %d\n", uint16(sourcePort))
        // sendSynPacketFor(srcPort)

      }()
    }

  }()

  injectPacket = func(packetData []byte) error {

    packet, err := parseTCP.ParseTCPPacket(packetData)
    if err != nil {
      return err
    }
    ip := packet.IP
    tcp := packet.TCP

    rly, ok := PORT_TO_DST[uint16(tcp.DstPort)]
    if !ok {
      infolog.Printf("%s:%d not in ports\n", ip.DstIP.String(), tcp.DstPort)
      os.Exit(1)
    }

    if tcp.FIN || tcp.RST {
      closeConnection(uint16(tcp.SrcPort))
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

      infolog.Println("Restoring Internet settings!")
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
    infolog.Println("NEGS", negs)
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
      infolog.Println("Exiting after signal.")
    }
  }()

  return unsub, injectPacket, nil

}


