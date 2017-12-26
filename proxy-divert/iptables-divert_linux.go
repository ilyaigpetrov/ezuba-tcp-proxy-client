package main

// #include "iptables-divert_linux.c"
import "C"
import (
  "errors"
  "github.com/ilyaigpetrov/ezuba-tcp-proxy-client/nettools"
  "os"
  "os/signal"
  "syscall"
  "log"
  "fmt"
)

var errlog = log.New(
  os.Stderr,
  "ERROR: ",
  log.Lshortfile,
)

var internalIP = "127.0.0.5"

func getFireSignalsChannel() chan os.Signal {

  c := make(chan os.Signal, 1)
  signal.Notify(c,
    // https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html
    syscall.SIGTERM, // "the normal way to politely ask a program to terminate"
    syscall.SIGINT, // Ctrl+C
    syscall.SIGQUIT, // Ctrl-\
    syscall.SIGKILL, // "always fatal", "SIGKILL and SIGSTOP may not be caught by a program"
    syscall.SIGHUP, // "terminal is disconnected"
  )
  return c

}

func exit() {

  syscall.Kill(syscall.Getpid(), syscall.SIGTERM)

}

var exitChan = getFireSignalsChannel()

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
  ip string
  port uint16
  clientSocket C.int
}

var PORT_TO_DST = make(map[uint16]realAddr)

func SubscribeToPacketsExcept(exceptions []string, packetHandler func([]byte)) /*(unsub func() error, injectPacket func([]byte) error)*/ (err error) {

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

      _, ip, tcp, _, err := nettools.ParseTCPPacket(packetData)
      if err != nil {
        // errlog.Println(err)
        continue
      }
      if ip.DstIP.String() != internalIP {
        continue
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
          ip: realIP,
          port: realPort,
          clientSocket: clientSocket,
        }

        defer delete(PORT_TO_DST, originalPort)
        result = C.createTcpConnectingSocket(C.CString(internalIP))
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

  return

}

func packetHandler(packetData []byte) {
  
}

func main() {

  err := SubscribeToPacketsExcept([]string{}, packetHandler)
  if err != nil {
    panic(err)
  }
  <-exitChan

}
