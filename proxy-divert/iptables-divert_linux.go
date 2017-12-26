package main

// #include "iptables-divert_linux.c"
import "C"
import (
  "errors"
  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/nettools"
  "os"
  "syscall"
  "log"
  "fmt"
  "net"
  "github.com/google/gopacket/layers"
  "github.com/coreos/go-iptables/iptables"
  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/at-fire"
  "github.com/tebeka/atexit"
)

var errlog = log.New(
  os.Stderr,
  "ERROR: ",
  log.Lshortfile,
)

var internalIP = "127.0.0.5"

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

func exit() {

  syscall.Kill(syscall.Getpid(), syscall.SIGTERM)

}

var exitChan = atFire.GetFireSignalsChannel()

func toErr(msg *C.char) error {
  return errors.New(C.GoString(msg))
}

var maxIpPacketSize = 65535
var packetBuffer = make([]byte, maxIpPacketSize)

func receive(s C.int) ([]byte, error) {

  ptr := C.CBytes(packetBuffer)
  n := int(C.recv(s, ptr, C.size_t(len(packetBuffer)), 0));
  if n < 0 {
    return []byte{}, toErr(C.getLastErrorMessage())
  }
  result := C.GoBytes(ptr, C.int(n))
  return result, nil

}

func write(s C.int, data []byte) (int, error) {

  n := C.write(s, C.CBytes(data), C.size_t(len(data)))
  if n < 0 {
    return 0, toErr(C.getLastErrorMessage())
  }
  return int(n), nil

}

type realAddr struct {
  realIP string
  realPort uint16
  clientSocket C.int
}

var PORT_TO_DST = make(map[uint16]realAddr)

func SubscribeToPacketsExcept(exceptions []string, packetHandler func([]byte)) (unsub func() error, injectPacket func([]byte) error, err error) {

  result := C.createTcpRawSocket()
  if result.error != nil {
    err = toErr(result.error)
    errlog.Println(err)
    return
  }
  rawSocket := result.socket
  go func(){

    defer C.close(rawSocket)
    for {
      packetData, err := receive(rawSocket)
      if err != nil {
        errlog.Println(err)
        break
      }

      _, ip, tcp, recompilePacket, err := nettools.ParseTCPPacket(packetData)
      if err != nil {
        // errlog.Println(err)
        continue
      }
      if ip.DstIP.String() != internalIP {
        continue
      }
      rly, ok := PORT_TO_DST[uint16(tcp.DstPort)]
      if !ok {
        fmt.Printf("Port %d not in base\n", tcp.DstPort)
        continue
      }
      if ip.DstIP.Equal(ip.SrcIP) {
        ip.DstIP = net.ParseIP(rly.realIP)
        tcp.DstPort = layers.TCPPort(rly.realPort)
        recompilePacket()
      }

      fmt.Printf("Internal: Packet from %s:%d to %s:%d\n", ip.SrcIP.String(), tcp.SrcPort, ip.DstIP.String(), tcp.DstPort)
      packetHandler(packetData)

    }

  }()

  result = C.createTcpListeningSocket(C.INADDR_ANY, 2222);
  if result.error != nil {
    err = toErr(result.error)
    errlog.Println(err)
    return
  }
  iptSocket := result.socket

  go func(){

    defer C.close(iptSocket)
    atexit.Register(func() { C.close(iptSocket) })
    for {
      /*
      typedef struct {
        int clientSocket;
        struct sockaddr_in sockaddr;
        int addrLen;
      } CONN;
      */
      conn := C.acceptTcpSocket(iptSocket);
      if conn.error != nil {
        err := toErr(conn.error)
        errlog.Println("Can't accept:", err)
        continue
      }

      sin := conn.sockaddr;
      originalIP := C.GoString(C.inet_ntoa(sin.sin_addr))
      originalPort := uint16(sin.sin_port)
      clientSocket := conn.clientSocket
      go func(){

        defer C.close(clientSocket)
        num := C.getdestaddrIptables(clientSocket, &sin);
        if (num != 0) {
          err := toErr(C.getLastErrorMessage())
          errlog.Println(err)
          return
        }
        realIP := C.GoString(C.inet_ntoa(sin.sin_addr))
        realPort := uint16(sin.sin_port)
        fmt.Printf("Accepted connection from %s:%d to %s:%d\n", originalIP, originalPort, realIP, realPort)

        PORT_TO_DST[originalPort] = realAddr{
          realIP: realIP,
          realPort: realPort,
          clientSocket: clientSocket,
        }

        defer delete(PORT_TO_DST, originalPort)
        result = C.createTcpConnectingSocket(C.CString(internalIP), C.uint(originalPort))
        if result.error != nil {
          err = toErr(result.error)
          errlog.Println(err)
          return
        }
        internalSocket := result.socket;

        defer C.close(internalSocket)
        for {
          packetData := make([]byte, maxIpPacketSize)
          fmt.Println("Reading from client socket...")
          packetData, err := receive(clientSocket)
          if err != nil {
            errlog.Println(err)
            break
          }
          fmt.Printf("Read %d bytes, writing to internal socket.\n", len(packetData))
          _, err = write(internalSocket, packetData)
          if err != nil {
            errlog.Println(err)
            break
          }
        }
      }()
    }

  }()

  injectPacket = func(packetData []byte) error {

    _, ip, tcp, _, err := nettools.ParseTCPPacket(packetData)
    if err != nil {
      return err
    }

    rly, ok := PORT_TO_DST[uint16(tcp.DstPort)]
    _ = rly
    if !ok {
      fmt.Printf("%s:%d not in ports\n", ip.DstIP.String(), tcp.DstPort)
      os.Exit(1)
    }

    /*
    if len(tcp.Payload) > 0 {
      _, err = rly.clientSocket.Write(tcp.Payload)
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
    */

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
    /*
    ipsports, err := hostsToIPs(exceptions)
    if err != nil {
      return nil, nil, err
    }
    ip := ipsports[0].ips[0]
    negs = []string{"!", "-d", ip}
    fmt.Println("NEGS", negs)
    */
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

func packetHandler(packetData []byte) {
  
}

func main() {

  unsub, _, err := SubscribeToPacketsExcept([]string{}, packetHandler)
  defer unsub()
  if err != nil {
    panic(err)
  }
  <-exitChan
  atexit.Exit(0)

}
