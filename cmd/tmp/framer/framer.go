// It doesn't work well, I just want to save this imperfect note for myself in case I need it in the future.
// It's a modified version of code on https://stackoverflow.com/a/43900205/521957
// If want to know how http2 session is initiated also look at https://github.com/golang/net/blob/master/http2/transport.go#L532
package main

import (
    "crypto/tls"
    "io"
    "log"
    "os"
    "bytes"

    "golang.org/x/net/http2"
    "golang.org/x/net/http2/hpack"
)

var infolog = log.New(os.Stdout,
    "", 0)

type proxyConn struct {
  tls.Conn
}

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

  front := "google.com:443"

  tlsConn, err := tls.Dial("tcp", front, cfg)
  if err != nil {
    panic(err)
  }
  sniffedTls := &proxyConn{*tlsConn}

  transport := &http2.Transport{}
  clientConn, err := transport.NewClientConn(sniffedTls)
  _ = clientConn // not used
  if err != nil {
    panic(err)
  }

  framer := http2.NewFramer(sniffedTls, sniffedTls)

  err = framer.WriteSettings()
  if err != nil {
    panic(err)
  }

  // clientConn.RoundTrip(req) is a way too.
    
  var headers bytes.Buffer
  enc := hpack.NewEncoder(&headers)
  enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "google.com"})
  enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
  enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
  enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})

  err = framer.WriteHeaders(http2.HeadersFrameParam{
    EndHeaders:    true,
    BlockFragment: headers.Bytes(),
    StreamID: 13,
  })
  if err != nil {
    panic(err)
  }
  LOOP:
  for {
    infolog.Println("Reading frame...")
    f, err := framer.ReadFrame()
    if err == io.EOF || err == io.ErrUnexpectedEOF {
      infolog.Println("EOF")
      break
    }
    switch err.(type) {
      case nil:
        infolog.Printf("FRAME: %v", f)

        setfr, ok := f.(*http2.SettingsFrame)
        if ok && !setfr.IsAck() {
          infolog.Println("Writing Settings ACK")
          err = framer.WriteSettingsAck()
          if err != nil {
            infolog.Println(err)
            panic(err)
          }
        } else if datafr, ok := f.(*http2.DataFrame); ok {
          if datafr.StreamEnded() {
            infolog.Println("Data stream ended! Writing go away!")
            err = framer.WriteGoAway(0, http2.ErrCodeNo, []byte{})
            if err != nil {
              panic(err)
            }
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

}
