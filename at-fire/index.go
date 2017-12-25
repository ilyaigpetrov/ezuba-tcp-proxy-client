package atFire

import (
  "os"
  "os/signal"
  "syscall"
)

func GetFireSignalsChannel() chan os.Signal {

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
