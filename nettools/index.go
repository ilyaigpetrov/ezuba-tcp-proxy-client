package nettools

import (
  "errors"
  "strings"
  "fmt"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "gopkg.in/oleiade/reflections.v1"
)

func ParseTCPPacket(packetData []byte) (
    packet gopacket.Packet,
    ip *layers.IPv4,
    tcp *layers.TCP,
    recompilePacket func() ([]byte, error),
    err error,
  ) {

  packet = gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)

  ipLayer := packet.Layer(layers.LayerTypeIPv4)
  if ipLayer == nil {
    err = errors.New("No IP layer!")
    return
  }
  ip = ipLayer.(*layers.IPv4)

  tcpLayer := packet.Layer(layers.LayerTypeTCP)
  if tcpLayer == nil {
    err = errors.New("No TCP layer!")
    return
  }
  tcp = tcpLayer.(*layers.TCP)

  recompilePacket = func() ([]byte, error) {

    options := gopacket.SerializeOptions{
      ComputeChecksums: true,
      FixLengths: true,
    }
    newBuffer := gopacket.NewSerializeBuffer()
    tcp.SetNetworkLayerForChecksum(ip)
    err := gopacket.SerializePacket(newBuffer, options, packet)
    if err != nil {
      return nil, err
    }
    return newBuffer.Bytes(), nil

  }

  return

}

func PrintPacket(packet gopacket.Packet) {

  ipLayer := packet.Layer(layers.LayerTypeIPv4)
  ip := ipLayer.(*layers.IPv4)
  tcpLayer := packet.Layer(layers.LayerTypeTCP)
  tcp := tcpLayer.(*layers.TCP)

  fmt.Printf("Internal: Packet from %s:%d to %s:%d %d", ip.SrcIP.String(), tcp.SrcPort, ip.DstIP.String(), tcp.DstPort, tcp.Seq)
  flags := strings.Split("FIN SYN RST PSH ACK URG ECE CWR NS", " ")
  for _, flag := range flags {
    val, err := reflections.GetField(tcp, flag)
    if err != nil {
      fmt.Println(err, "REFLECT ERROR!")
    }
    if val.(bool) {
      fmt.Printf(" %s", flag)
    }
  }
  fmt.Printf("\n")

}
