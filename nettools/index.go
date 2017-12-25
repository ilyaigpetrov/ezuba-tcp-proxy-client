package nettools

import (
  "errors"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
)

func ParseTCPPacket(packetData []byte) (packet gopacket.Packet, ip *layers.IPv4, tcp *layers.TCP, recompilePacket func() ([]byte, error), err error) {

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
