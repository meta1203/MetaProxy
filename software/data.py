from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
import struct
import random

def byte_pair(byte):
  return (byte, struct.unpack('>B', byte)[0])

class sockEncrypt:
  def __init__(self, sock):
    self.__sock = sock
    self.crypt = None
  def send(self, data):
    if self.crypt is not None:
      return self.__sock.send(self.crypt.encrypt(data))
    else:
      return self.__sock.send(data)
  def recv(self, n):
    data = self.__sock.recv(n)
    if self.crypt is not None:
      return self.crypt.decrypt(data)
    else:
      return data
  def enable_crypt(self, cypher):
    self.crypt = cypher
    print(self.crypt)
  def close(self):
    self.__sock.close()
    
def genString(length):
  var = ''
  for x in range(length):
    var += randomLetter()
  return var

abc = 'abcdef1234567890'
def randomLetter():
  return abc[random.randint(0,15)]

def decode_public_key(bytes):
  return RSA.importKey(bytes)

def encode_public_key(key):
  var = key.publickey().exportKey(format="DER")
  return var

def gen_key_pair():
  return RSA.generate(1024)

def generate_secret():
  found = False
  while not found:
    data = Random.get_random_bytes(16)
    if '\x00' in data:
      continue
    else:
      found = True
  return data

def encrypt_secret(secret, pubKey):
  cipher = PKCS1_v1_5.new(pubKey)
  return cipher.encrypt(secret)

def decrypt_secret(en_Secret, privKey):
  cipher = PKCS1_v1_5.new(privKey)
  var = cipher.decrypt(en_Secret, '...')
  return var

class Encryption:
  def __init__(self, sharedSecret):
    self.cypher = ""

  def encrypt(self, bytes):
    return self.cypher.encrypt(bytes)

  def decrypt(self, bytes):
    return self.cypher.decrypt(bytes)

class DataIO:
  def __init__(self, inMethod, outMethod):
    setattr(self,'read',inMethod)
    setattr(self,'write',outMethod)

  def activateEncryption(self, secret):
    self.crypt = Encryption(secret)

# IO METHODS!

def readInt(sock):
  return struct.unpack('>i', sock.recv(4))[0]

def readByte(sock):
  return struct.unpack('>b', sock.recv(1))[0]

def readLong(sock):
  return struct.unpack('>l', sock.recv(8))[0]

def readShort(sock):
  return struct.unpack('>h', sock.recv(2))[0]

def readUnsignedShort(sock):
  return struct.unpack('>H', sock.recv(2))[0]

def readUnsignedByte(sock):
  return struct.unpack('>B', sock.recv(1))[0]

def readDouble(sock):
  return struct.unpack('>d', sock.recv(1))[0]

def readFloat(sock):
  return struct.unpack('>f', sock.recv(1))[0]

def readString(sock):
  length = struct.unpack('>h', sock.recv(2))[0]
  return sock.recv(length*2).decode('utf-16be')

def readMetadata(sock):
  temp_byte = struct.unpack('>b', sock.recv(1))[0]
  ret = []
  while temp_byte != 127:
    index = temp_byte & 0x1F
    typ = temp_byte >> 5
    if typ == 0:
      var = struct.unpack('>b', sock.recv(1))[0]
    if typ == 1:
      var = struct.unpack('>h', sock.recv(2))[0]
    if typ == 2:
      var = struct.unpack('>i', sock.recv(4))[0]
    if typ == 4:
      length = struct.unpack('>h', sock.recv(2))[0]
      var = sock.recv(length*2).decode('utf-16be')
    ret.append((typ, var))
    temp_byte = struct.unpack('>b', sock.recv(1))[0]
  return ret

def readInventory(sock):
  var = [0]
  var[0] = struct.unpack('>h', sock.recv(2)[0])
  if var[0] != -1:
    var.append(struct.unpack('>b', sock.recv(1))[0])
    var.append(struct.unpack('>h', sock.recv(2))[0])
    if var[2] != -1:
      var.append(sock.recv(var[2])[0])
  return var
    
def readInventoryArray(sock):
  length = struct.unpack('>h', sock.recv(2))[0]
  var = range(length)
  for x in range(length):
    var[x] = []
    var[x].append(struct.unpack('>h', sock.recv(2)))
    var[x].append(struct.unpack('>b', sock.recv(1)))
    var[x].append(struct.unpack('>h', sock.recv(2)))
    if var[x][2]:
      var[x].append(sock.recv(var[2]))

def readObjectData(sock):
  var = []
  var.append(struct.unpack('>i', sock.recv(4))[0])
  if var[0]:
    var.append(struct.unpack('>h', sock.recv(2))[0])
    var.append(struct.unpack('>h', sock.recv(2))[0])
    var.append(struct.unpack('>h', sock.recv(2))[0])
  return var

def readIntArray(sock):
  length = struct.unpack('>b', sock.recv(1))[0]
  var = []
  for x in range(length):
    var.append(struct.unpack('>i', sock.recv(4))[0])
  return var
    
def readByteArray(sock):
  length = struct.unpack('>h', sock.recv(2))[0]
  print(length)
  return sock.recv(length)

def readUnsignedByteArray(sock):
  length = struct.unpack('B', sock.recv(4))[0]
  var = []
  for x in range(length):
    var.append(struct.unpack('>b', sock.recv(1))[0])
  return var
    
def readTriByteArray(sock):
  length = struct.unpack('i', sock.recv(4))[0] * 3
  var = []
  for x in range(length):
    var.append(struct.unpack('>b', sock.recv(1))[0])
  return var
    
def readDataArray(sock):
  chunkNum = struct.unpack('>h', sock.recv(2))[0]
  arrayLen = struct.unpack('>i', sock.recv(4))[0]
  ret = ([], [])
  for x in range(arrayLen):
    ret[0] = []
    ret[0].append(struct.unpack('>b', sock.recv(1))[0])
  for x in range(chunkNum):
    ret[1][x] = []
    ret[1][x].append(struct.unpack('>i', sock.recv(4))[0])
    ret[1][x].append(struct.unpack('>i', sock.recv(4))[0])
    ret[1][x].append(struct.unpack('>h', sock.recv(2))[0])
    ret[1][x].append(struct.unpack('>h', sock.recv(2))[0])
  return ret

# DO THE WRITINZ

def writeByte(sock, data):
  sock.send(struct.pack('>b', data))

def writeShort(sock, data):
  sock.send(struct.pack('>h', data))
    
def writeUnsignedShort(sock, data):
  sock.send(struct.pack('>H', data))

def writeInt(sock, data):
  sock.send(struct.pack('>i', data))

def writeLong(sock, data):
  sock.send(struct.pack('>l', data))

def writeUnsignedByte(sock, data):
  sock.send(struct.pack('>B', data))

def writeFloat(sock, data):
  sock.send(struct.pack('>f', data))

def writeDouble(sock, data):
  sock.send(struct.pack('>d', data))

def writeString(sock, data):
  length = len(data)
  toSend = data.encode('utf-16be')
  sock.send(struct.pack('>h', length))
  sock.send(toSend)

def writeMetadata(sock, data):
  for current in range(len(data)):
    test_byte = data[current][0] << 5
    test_byte += current
    sock.send(struct.pack('>b', test_byte))
    if data[current][0] == 0:
      sock.send(struct.pack('>b', data[current][1]))
    if data[current][0] == 1:
      sock.send(struct.pack('>h', data[current][1]))
    if data[current][0] == 2:
      sock.send(struct.pack('>i', data[current][1]))
    if data[current][0] == 4:
      length = len(data[current][1])
      sock.send(struct.pack('>h', length))
      toSend = data[current][1].encode('utf-16be')
      sock.send(toSend)
  sock.send(struct.pack('>b', 127))

def writeInventory(sock, data):
  sock.send(struct.pack('>h', data[0]))
  if data[0] == -1:
    return
  sock.send(struct.pack('>b', data[1]))
  size = data[2]
  sock.send(struct.pack('>h', size))
  if size > 0:
    sock.send(data[3])
      
def writeObjectData(sock, data):
  sock.send(struct.pack('>i', data[0]))
  if data[0]:
    sock.send(struct.pack('>h', data[1]))
    sock.send(struct.pack('>h', data[2]))
    sock.send(struct.pack('>h', data[3]))
      
def writeIntArray(sock, data):
  sock.send(struct.pack('>i', len(data)))
  for x in data:
    sock.send(struct.pack('>i', x))

def writeByteArray(sock, data):
  sock.send(struct.pack('>h', len(data)))
  print('Byte array length:')
  print(sock.send(data))

def writeUnsignedByteArray(sock, data):
  sock.send(struct.pack('>i', len(data)))
  for x in data:
    sock.send(struct.pack('>b', x))

def writeTriByteArray(sock, data):
  sock.send(struct.pack('>i', len(data/3)))
  for x in data:
    sock.send(struct.pack('>b', x))

def writeDataArray(sock, data):
  sock.send(struct.pack('>h', len(data[0])))
  sock.send(struct.pack('>i', len(data[1])))
  for x in data[0]:
    sock.send(struct.pack('>b', x))
  for x in data[1]:
    sock.send(struct.pack('>i', x[0]))
    sock.send(struct.pack('>i', x[1]))
    sock.send(struct.pack('>h', x[2]))
    sock.send(struct.pack('>h', x[3]))

def writeInventoryArray(sock, data):
  sock.send(struct.pack('>h', len(data)))
  for x in data:
    sock.send(struct.pack('>h', x[0]))
    if x[0] != -1:
      sock.send(struct.pack('>b', x[1]))
      sock.send(struct.pack('>h', x[2]))
      if x[2] != -1:
        for y in x[3]:
          sock.send(struct.pack('>b', y))

# NOT IO METHODS! (MC Data Types)

MC_int = DataIO(readInt, writeInt)
MC_byte = DataIO(readByte, writeByte)
MC_long = DataIO(readLong, writeLong)
MC_ubyte = DataIO(readUnsignedByte, writeUnsignedByte)
MC_string = DataIO(readString, writeString)
MC_float = DataIO(readFloat, writeFloat)
MC_double = DataIO(readDouble, writeDouble)
MC_metadata = DataIO(readMetadata, writeMetadata)
MC_inventory = DataIO(readInventory, writeInventory)
MC_objectdata = DataIO(readObjectData, writeObjectData)
MC_intarray = DataIO(readIntArray, writeIntArray)
MC_bytearray = DataIO(readByteArray, writeByteArray)
MC_short = DataIO(readShort, writeShort)
MC_ushort = DataIO(readUnsignedShort, writeUnsignedShort)
MC_dataarray = DataIO(readDataArray, writeDataArray)
MC_tribytearray = DataIO(readTriByteArray, writeTriByteArray)
MC_inventoryarray = DataIO(readInventoryArray, writeInventoryArray)
MC_ubytearray = DataIO(readUnsignedByteArray, writeUnsignedByteArray)
