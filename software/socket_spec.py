from Crypto.Cypher import AES

class Stream:
  def __init__(self, sock_pair):
    self._sock_pair = sock_pair
    self._sock_pair.setblocking(0)
    self._crypt = None
    self._buffer = ""
    self.closed = False
  
  def read_into(self, n):
    try:
      data = self._sock_pair.recv(n)
    except:
      return False
    if self._crypt is not None:
      data = self._crypt.decrypt(data)
    self._buffer += data
    return True
    
  def recv(self, n):
    if self.closed:
      return
    if n < len(self._buffer):
      ret = self._buffer[0:n]
      self._buffer = self._buffer[n:]
      return ret
    if n > len(self._buffer):
      self.read_into(n - len(self._buffer))
      return recv(n)
    else:
      ret = self._buffer
      self._buffer = ""
      return ret
    
  def send(self, bytes):
    if self.closed:
      return
    if self._crypt is not None:
      bytes = self._crypt.encrypt(bytes)
    return self._sock_pair.sendall(bytes)
    
  def close(self):
    if not self.closed:
      self._sock_pair.close()
      self.closed = True
      self._buffer = ""
  
  def start_encryption(self, secret):
    self._crypt = AES.new(secret, AES.MODE_CFB, secret)