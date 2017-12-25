package proxyDivert

import (
  "strings"
  "errors"
  "fmt"
  "net"
)

type ipsAndPort struct {
  ips []string
  port string
}

func hostToIPs(host string) (*ipsAndPort, error) {

  parts := strings.Split(host, ":")
  if len(parts) != 2 {
    return nil, errors.New(fmt.Sprintf(`"%s" must be in format hostname:port`, host))
  }
  port := parts[1]
  portless := parts[0]
  ips, err := net.LookupHost(portless)
  if err != nil {
    return nil, err
  }

  return &ipsAndPort{
    ips: ips,
    port: port,
  }, nil

}

func hostsToIPs(hosts []string) (results []*ipsAndPort, err error) {

  for _, host := range hosts {
    ipsport, err := hostToIPs(host)
    if err != nil {
      return nil, err
    }
    results = append(results, ipsport)
  }
  return results, nil

}
