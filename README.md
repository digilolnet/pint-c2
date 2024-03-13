# Pint C2
This is a C2 that uses various techniques to evade from eBPF based security monitoring.

## Features

* [Userland exec / reflective ELF loading](https://grugq.github.io/docs/ul_exec.txt).
* Event spamming / resource exhaustion.
* Sockets and TCP connection using io_uring.

## Commands

* `ulexec [command]`
* `memfd [command]`
* `noise [on/off]`
