package freeport

import (
	"net"
        "fmt"
)

// GetFreePort asks the kernel for a free open port that is ready to use.
func GetFreePort(hostname string) (int, error) {
        if hostname == "" {
          hostname = "localhost"
        }
	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:0", hostname))
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

