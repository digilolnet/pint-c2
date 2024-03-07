# Pint C2
This is a C2 that uses various techniques to evade from eBPF based security monitoring

## Features

* [Userland exec / reflective ELF loading](https://grugq.github.io/docs/ul_exec.txt).
* Event spamming / resource exhaustion.
* Networking using io_uring to evade system call monitoring. - TODO
