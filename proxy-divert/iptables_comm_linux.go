package proxyDivert

// #include "iptables_comm_linux.c"
// void go_handlePacket_cgo(int, void*, int);
import "C"
import (
  "errors"
  "fmt"
)

//export go_handlePacket
func go_handlePacket(s C.int, packetBuffer unsafe.Pointer, n C.int) {

  fmt.Println("CALLED")

}

func SubscribeToPacketsExcept(exceptions []string, packetHandler func([]byte)) /*(unsub func() error, injectPacket func([]byte) error)*/ (err error) {

  result := C.createTcpSocket()
  if result.error {
    err = errors.New(result.error)
    return
  }
  socket = result.socket
  go func(){

    C.subscribeToTcpPackets(socket, C.go_handlePacket_cgo)

  }()

}
