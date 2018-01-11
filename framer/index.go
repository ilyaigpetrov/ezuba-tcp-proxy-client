package main

import (
    "crypto/tls"
    //"io"
    "log"
    "os"
    //"bytes"
    "net/http"
    "io/ioutil"

    "golang.org/x/net/http2"
    "golang.org/x/net/http2/hpack"
)

var infolog = log.New(os.Stdout,
    "", 0)

type proxyConn struct {
  tls.Conn
}

var dec = hpack.NewDecoder(4096, func(f hpack.HeaderField) {})

func (w *proxyConn) Read(b []byte) (n int, err error) {
  n, err = w.Conn.Read(b)
  infolog.Println("READ:", string(b))
  return
}

func (w *proxyConn) Write(b []byte) (n int, err error) {
  n, err = w.Conn.Write(b)
  infolog.Println("WRITE:", string(b))
  return
}

func main() {

  cfg := new(tls.Config)
  cfg.NextProtos = append([]string{"h2"}, cfg.NextProtos...)

  front := "www.google.com:443"

  tlsConn, err := tls.Dial("tcp", front, cfg)
  if err != nil {
    panic(err)
  }
  sniffedTls := &proxyConn{*tlsConn}

  transport := &http2.Transport{}
  clientConn, err := transport.NewClientConn(sniffedTls)
  if err != nil {
    panic(err)
  }
  req, err := http.NewRequest("GET", "/foo", nil)
  if err != nil {
    infolog.Println(err)
    return
  }
  req.Host = "domain-fronting-test.appspot.com"
  resp, err := clientConn.RoundTrip(req)
  if err != nil {
    infolog.Println(err)
    return
  }
  defer resp.Body.Close()
  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    infolog.Println(err)
    return
  }
  infolog.Println(string(body))

  /*
  framer := http2.NewFramer(sniffedTls, sniffedTls)

  err = framer.WriteSettings()
  if err != nil {
    infolog.Println(err)
    panic(err)
  }

  var headers bytes.Buffer
  enc := hpack.NewEncoder(&headers)
  enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "domain-fronting-test.appspot.com"})

  infolog.Println("BYTES IN HEADER:", len(headers.Bytes()), headers.Bytes())

  err = framer.WriteHeaders(http2.HeadersFrameParam{
    EndHeaders:    true,
    BlockFragment: headers.Bytes(),
    StreamID: 1,
  })
  if err != nil {
    infolog.Println(err)
    panic(err)
  }
  LOOP:
  for {
    infolog.Println("Reading frame...")
    f, err := framer.ReadFrame()
    if err == io.EOF || err == io.ErrUnexpectedEOF {
      break
    }
    switch err.(type) {
      case nil:
        infolog.Printf("FRAME: %v", f)
        if _, ok := f.(*http2.SettingsFrame); ok {
          infolog.Println("Writing Settings ACK")
          err = framer.WriteSettingsAck()
          if err != nil {
            infolog.Println(err)
            panic(err)
          }
        }
      case http2.ConnectionError:
        // Ignore. There will be many errors of type "PROTOCOL_ERROR, DATA
        // frame with stream ID 0". Presumably we are abusing the framer.
        infolog.Println("CON ERR:", err)
      default:
        infolog.Println(err, framer.ErrorDetail())
        break LOOP
    }
  }
  */

}
