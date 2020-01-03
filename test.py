import rsa
import zlib
import random
import struct
import socket
import time
import argparse
import ctypes

zlibdll = ctypes.CDLL('libz.so.1.2.11')
zlibdll.crc32_combine.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_long]
zlibdll.crc32_combine.restype = ctypes.c_long

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--port', type=int, default=1337, help='port, to send packets to')
parser.add_argument('-i', '--packet', required=True, help='packet id')
parser.add_argument('-k', '--key', required=True, help='private key file')
parser.add_argument('-b', '--binary', required=True, help='binary file')
args = parser.parse_args()

with open(args.key, mode='r') as _:
	key_data = _.read()
private_key = rsa.PrivateKey.load_pkcs1(key_data)

with open(args.binary, 'r') as _:
	data = _.read()

data_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
port = args.port
packet_id = int(eval(args.packet))

sequence_div = 2713
sequence_mod = random.randint(0, sequence_div - 1)

message_div = 257
message_mod = random.randint(0, message_div - 1)

data_len = len(data)
crc32cmb = zlib.crc32(data, 0) & 0xffffffff

sequence = 0
data_crc = 0
for _ in range(9999):
	xor_key = random.randint(0, 0xffff)
	checksums = random.randint(1, 24)
	message = struct.pack('!IIHH', packet_id, sequence, xor_key, checksums)
	xor_key |= xor_key << 16
	while checksums:
		# data_crc = zlib.crc32(data, data_crc) & 0xffffffff
		data_crc = zlibdll.crc32_combine(data_crc, crc32cmb, data_len)
		if sequence % sequence_div == sequence_mod:
			message += struct.pack('!I', (data_crc + 3) ^ xor_key)
		else:
			message += struct.pack('!I', data_crc ^ xor_key)
		sequence += 1
		checksums -= 1
	signature = rsa.sign(message, private_key, 'SHA-256')
	if _ % message_div == message_mod:
		message = message[:12] + '*' + message[13:]
	message += signature
	data_socket.sendto(message, ('127.0.0.1', port))
	time.sleep(0.01 * random.random())
data_socket.close()
