package main

import (
  "golang.org/x/net/http2"
  "net/http"
  "fmt"
  "time"
  "io/ioutil"
)

func main() {

  tr := &http.Transport{
    MaxIdleConns:       10,
    IdleConnTimeout:    30 * time.Second,
    DisableCompression: true,
  }
  err := http2.ConfigureTransport(tr)
  if err != nil {
    panic(err)
  }
  client := &http.Client{Transport: tr}
  req, err := http.NewRequest("GET", "https://www.google.com", nil)
  if err != nil {
    panic(err)
  }
  req.Host = "domain-fronting-test.appspot.com"
  resp, err := client.Do(req)
  if err != nil {
    panic(err)
  }
  defer resp.Body.Close()
  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    panic(err)
  }
  fmt.Println(string(body))

}
