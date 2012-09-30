import sys
import socket
from sthread import Serve_Thread

port = int(sys.argv[1])
defaultHost = sys.argv[2]
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('', port))
sock.listen(1)
print("Bound!")
while True:
  sock2, addr = sock.accept()
  print("Accepted!")
  curr = Serve_Thread(sock2, defaultHost)
  curr.start()