from Crypto.Cipher import AES

class Stream:
  def __init__(self, sock_pair):
    self._sock_pair = sock_pair
    self._sock_pair.setblocking(0)
    self.read = 0
    self.wrote = 0
    self._crypt = None
    self._buffer = ""
    self._obuffer = ""
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
      self.read += n
      return ret
    if n > len(self._buffer):
      return
    else:
      ret = self._buffer
      self._buffer = ""
      self.read += n
      return ret

  def send(self, bytes):
    if self._crypt is not None:
      bytes = self._crypt.encrypt(bytes)
    self._obuffer += bytes

  def close(self):
    if not self.closed:
      self._sock_pair.close()
      self.closed = True
      self._buffer = ""

  def start_encryption(self, secret):
    self._crypt = AES.new(secret, AES.MODE_CFB, secret)
    self._buffer = self._crypt.decrypt(self._buffer)

  def dump(self):
    ret = self._buffer
    print(len(ret))
    self._buffer = ""
    return ret

  def next(self):
    return self._buffer[0]

  def read_ahead(self, n):
    return self._buffer[n]

  def stats(self):
    return (self.read, self.wrote, len(self._buffer))
  def flush(self):
    if self.closed:
      return
    self._sock_pair.send(self._obuffer)
    self.wrote += len(self._obuffer)