import threading
import socket
import struct
from data import (MC_int, MC_byte, MC_long, MC_ubyte, MC_string, MC_float, MC_double, 
MC_metadata, MC_inventory, MC_objectdata, MC_intarray, MC_bytearray, 
MC_short, MC_ushort, MC_dataarray, MC_tribytearray, Encryption, genString, 
MC_inventoryarray, MC_ubytearray, decode_public_key, encode_public_key, 
gen_key_pair, generate_secret, decrypt_secret, encrypt_secret)
from socket_spec import Stream
import time
from parsing import packetsList
from Crypto import Random

class Serve_Thread(threading.Thread):
  def __init__(self, csock, toConnect):
    self.csock = Stream(csock)
    lolsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lolsock.connect((toConnect, 25565))
    self.ssock = Stream(lolsock)
    self.sId = "-" # genString(10)
    self.sRSA = gen_key_pair()
    self.ccheck = Random.get_random_bytes(4)
    self.connected = False
    threading.Thread.__init__(self)

  def parse_server(self, byte):
    if byte == 0xfd:
      self.cId = MC_string.read(self.ssock)
      pub = MC_bytearray.read(self.ssock)
      self.cRSA = decode_public_key(pub)
      self.scheck = MC_bytearray.read(self.ssock)
      # relay
      byte = encode_public_key(self.sRSA)
      MC_ubyte.write(self.csock, 0xfd)
      MC_string.write(self.csock, self.sId)
      MC_bytearray.write(self.csock, byte)
      MC_bytearray.write(self.csock, self.ccheck)
    elif byte == 0xfc:
      print(MC_short.read(self.ssock))
      print(MC_short.read(self.ssock))
      MC_ubyte.write(self.csock,0xfc)
      MC_short.write(self.csock,0)
      MC_short.write(self.csock,0)
      self.csock.start_encryption(self.shared_secret)
      self.ssock.start_encryption(self.shared_secret)
      time.sleep(0.1)
    elif byte == 0xff:
      test = MC_string.read(self.ssock)
      if "[Reconnect]" in test:
        toConnect = test[11:].split(':')
        reconnect(toConnect[0], int(toConnect[1]))
      else:
        MC_ubyte.write(self.csock, byte)
        MC_string.write(self.csock, test)
    else:
      try:
        MC_ubyte.write(self.csock, byte)
        for x in packetsList[byte]:
          x.write(self.csock, x.read(self.ssock))
        print("Wrote packet: " + str(byte) + " S -> C")
      except:
        dumped = self.ssock.dump()
        print(dumped)
        self.ssock.close()
    
  def parse_client(self, byte):
    if byte == 0xfc:
      self.shared_secret = decrypt_secret(MC_bytearray.read(self.csock), self.sRSA)
      print(decrypt_secret(MC_bytearray.read(self.csock), self.sRSA) == self.ccheck)
      # relay
      MC_ubyte.write(self.ssock, 0xfc)
      print('Sending encryption...')
      MC_bytearray.write(self.ssock, encrypt_secret(self.shared_secret, self.cRSA))
      MC_bytearray.write(self.ssock, encrypt_secret(self.scheck, self.cRSA))
    elif byte == 0x02:
      MC_ubyte.write(self.ssock, 0x02)
      MC_byte.write(self.ssock, MC_byte.read(self.csock))
      self.username = MC_string.read(self.csock)
      print(self.username)
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
    self.ssock = Stream(lolsock)
    
  def run(self):
    while (not self.ssock.closed) and (not self.csock.closed):
      if self.csock.read_into(4096):
        # print(self.csock.stats())
        data = self.csock.recv(1)
        if not data:
          print('Breaking!')
          break
        data = struct.unpack('>B', data)[0]
        print("Client Packet ID: " + str(data))
        self.parse_client(data)
      # Other side...
      if self.ssock.read_into(4096):
        # print(self.ssock.stats())
        data = self.ssock.recv(1)
        if not data:
          print('Breaking!')
          break
        data = struct.unpack('>B', data)[0]
        print("Server Packet ID: " + str(data))
        self.parse_server(data)
    self.csock.close()
    self.ssock.close()
