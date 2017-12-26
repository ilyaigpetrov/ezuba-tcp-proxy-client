package main

// #include "iptables-divert_linux.c"
import "C"
import (
  "errors"
  "fmt"
  "net"
  "encoding/binary"
  //"github.com/ilyaigpetrov/ezuba-tcp-proxy-client/nettools"
  "os"
  "os/signal"
  "syscall"
)

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

func int2ip(nn uint32) net.IP {
  ip := make(net.IP, 4)
  binary.BigEndian.PutUint32(ip, nn)
  return ip
}

func SubscribeToPacketsExcept(exceptions []string, packetHandler func([]byte)) /*(unsub func() error, injectPacket func([]byte) error)*/ (err error) {

  result := C.createTcpRawSocket()
  if result.error != nil {
    err = toErr(result.error)
    return
  }
  rawSocket := result.socket
  defer C.close(rawSocket)
  go func(){

    maxIpPacketSize := 65535;
    for {
      packetData := make([]byte, maxIpPacketSize)
      n := int(C.recv(rawSocket, C.CBytes(packetData), C.size_t(maxIpPacketSize), 0));
      if (n > 0) {
        packetHandler(packetData[:n])
      }
    }

  }()

  result = C.createTcpListeningSocket(2222);
  if result.error != nil {
    err = toErr(result.error)
    return
  }
  iptSocket := result.socket
  defer C.close(iptSocket)
  go func(){

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
        fmt.Println("Can't accept:", toErr(conn.error))
        exit()
        return
      }

      sin := conn.sockaddr;
      //C.printf("Packet from %s:%d\n", C.inet_ntoa(sin.sin_addr), C.ntohs(sin.sin_port));

      ip := C.inet_ntoa(sin.sin_addr)
      fmt.Printf("Accepted from %s:%d\n", ip, int(sin.sin_port))
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
