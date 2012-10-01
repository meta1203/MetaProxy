import threading
import socket
import struct
from data import (MC_int, MC_byte, MC_long, MC_ubyte, MC_string, MC_float, MC_double, 
MC_metadata, MC_inventory, MC_objectdata, MC_intarray, MC_bytearray, 
MC_short, MC_ushort, MC_dataarray, MC_tribytearray, Encryption, 
MC_inventoryarray, MC_ubytearray, sockEncrypt, decode_public_key, encode_public_key, 
gen_key_pair, generate_secret, decrypt_secret, encrypt_secret)

from parsing import packetsList
from Crypto import Random

class Serve_Thread(threading.Thread):
  def __init__(self, csock, toConnect):
    self.csock = sockEncrypt(csock)
    lolsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lolsock.connect((toConnect, 25565))
    self.ssock = sockEncrypt(lolsock)
    self.sId = "".join("%02x" % ord(c) for c in Random.get_random_bytes(10))
    self.sRSA = gen_key_pair()
    self.ccheck = Random.get_random_bytes(4)
    self.s_shared_secret = generate_secret()
    print("Bytes: " + ccheck)
    threading.Thread.__init__(self)

  def parse_server(self, byte):
    if byte == 0xfd:
      self.cId = MC_string.read(self.ssock)
      pub = MC_bytearray.read(self.ssock)
      print(pub)
      self.cRSA = decode_public_key(pub)
      byte = encode_public_key(self.sRSA)
      self.scheck = MC_bytearray.read(self.ssock)
      # relay
      MC_ubyte.write(self.csock, int(0xfd))
      MC_string.write(self.csock, self.sId)
      MC_bytearray.write(self.csock, byte)
      MC_bytearray.write(self.csock, self.ccheck)
    elif byte == 0xfc:
      MC_short.read(self.ssock)
      MC_short.read(self.ssock)
      self.ssock.enable_crypt(self.s_shared_secret)
    elif byte == 0xff:
      test = MC_string.read(self.ssock)
      if "[Reconnect]" in test:
        toConnect = test[11:].split(':')
        reconnect(toConnect[0], int(toConnect[1]))
      else:
        MC_ubyte.write(self.csock, byte)
        MC_string.write(self.csock, test)
    else:
      MC_ubyte.write(self.csock, byte)
      for x in packetsList[byte]:
        x.write(self.csock, x.read(self.ssock))
      print("Wrote packet: " + str(byte) + " S -> C")
    
  def parse_client(self, byte):
    if byte == 0xfc:
      self.c_shared_secret = decrypt_secret(MC_bytearray.read(self.csock), self.sRSA)
      MC_bytearray.read(self.csock)
      MC_ubyte.write(self.csock,0xfc)
      MC_short.write(self.csock,0)
      MC_short.write(self.csock,0)
      self.csock.enable_crypt(self.c_shared_secret)
      # relay
      MC_ubyte.write(self.ssock, 0xfc)
      MC_bytearray.write(self.ssock, encrypt_secret(self.s_shared_secret, self.sRSA))
      MC_bytearray.write(self.ssock, )
    elif byte == 0x02:
      MC_ubyte.write(self.ssock, 0x02)
      MC_byte.write(self.ssock, MC_byte.read(self.csock))
      self.username = MC_string.read(self.csock)
      MC_string.write(self.ssock, self.username)
      MC_string.write(self.ssock, MC_string.read(self.csock))
      MC_int.write(self.ssock, MC_int.read(self.csock))
    else:
      MC_ubyte.write(self.ssock, int(byte))
      for x in packetsList[byte]:
        x.write(self.ssock, x.read(self.csock))
      print("Wrote packet: " + str(byte) + " C -> S")
    
  def reconnect(server, port):
    print("Connecting to: " + server)
    print("on port: " + str(port))
    lolsock = socket.socket(AF_INET, AF_STREAM)
    lolsock.connect((server, port))
    self.ssock = sockEncrypt(lolsock)
    
  def run(self):
    while True:
      data = self.csock.recv(1)
      if not data: break
      self.parse_client(struct.unpack('>B', data))
      data = self.csock.recv(1)
      if not data:
        MC_ubyte()
      self.parse_server(struct.unpack('>B', data))
