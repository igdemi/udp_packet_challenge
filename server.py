import socket
import Queue
import threading
import struct
import time
import rsa
import zlib
import ctypes
import argparse

zlibdll = ctypes.CDLL('libz.so.1.2.11')
zlibdll.crc32_combine.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_long]
zlibdll.crc32_combine.restype = ctypes.c_long

def read_packet(key, binary):
	with open(key, 'r') as key_file:
		key_data = key_file.read()
		n, e = 0, 0
		for b in key_data[:64]:
			n <<= 8
			n += ord(b)
		for b in key_data[64:]:
			e <<= 8
			e += ord(b)
		with open(binary, 'r') as bin_file:
			# bin_data = bin_file.read()
			# data_len = len(bin_data)
			# data_crc32 = zlib.crc32(bin_data) & 0xffffffff
			data_len = 0
			data_crc32 = 0
			bin_data = bin_file.read(65536)
			read_len = len(bin_data)
			while read_len:
				data_len += read_len
				data_crc32 = zlib.crc32(bin_data, data_crc32)
				bin_data = bin_file.read(65536)
				read_len = len(bin_data)
			data_crc32 &= 0xffffffff
			crc32_list = [data_crc32]
			data_len2 = data_len
			for _ in range(31):
				data_crc32 = zlibdll.crc32_combine(data_crc32, data_crc32, data_len2)
				data_len2 <<= 1
				crc32_list.append(data_crc32)
			return (rsa.PublicKey(n, e), data_len, tuple(crc32_list))

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--port', type=int, default=1337, help='port, to receive packets on')
parser.add_argument('-d', '--delay', type=int, default=0, help='delay, (in seconds) for writing to log files')
parser.add_argument('-k', '--keys', required=True, help='a dictionary of {packet_id: key_file_path} mappings')
parser.add_argument('-b', '--binaries', required=True, help='a dictionary of {packet_id: binary_path} mappings')
args = parser.parse_args()

port = args.port
delay = args.delay

arg_key = eval(args.keys)
arg_bin = eval(args.binaries)

packets = {}
for i in arg_key.keys():
	packets[eval(i)] = read_packet(arg_key[i], arg_bin[i])

checksum_cache = {}
for i in packets.keys():
	checksum_cache[i] = (0, packets[i][2][0])

signature_log = open('verification_failures.log', 'w')
checksum_log = open('checksum_failures.log', 'w')

latency = 0.1
thread_function_event = threading.Event()

signature_queue = Queue.Queue()

def signature_thread_function():
	while not thread_function_event.is_set():
		try:
			t, l = signature_queue.get(True, latency)
			s = t + delay - time.time()
			if latency < s:
				thread_function_event.wait(s)
			signature_log.write(l)
			signature_log.flush()
		except Queue.Empty:
			pass

checksum_queue = Queue.Queue()

def checksum_thread_function():
	while not thread_function_event.is_set():
		try:
			t, l = checksum_queue.get(True, latency)
			s = t + delay - time.time()
			if latency < s:
				thread_function_event.wait(s)
			checksum_log.write(l)
			checksum_log.flush()
		except Queue.Empty:
			pass

data_queue = Queue.Queue()

def data_thread_function():
	while not thread_function_event.is_set():
		try:
			data = data_queue.get(True, latency)
			if len(data) < 12:
				print '? len(data): ', len(data)
				continue
			packet_id, sequence, xor_key, checksums = struct.unpack_from('!IIHH', data)
			message_len = 12 + 4 * checksums
			if len(data) < message_len + 64:
				print '? len(data): ', len(data)
				continue
			message, signature = data[:message_len], data[message_len:message_len+64]
			try:
				pub_key, data_len, data_crc32 = packets[packet_id]
				rsa.verify(message, signature, pub_key)
				checksum_iteration, iteration_crc32 = checksum_cache[packet_id]
				if checksum_iteration <= sequence and sequence < checksum_iteration + 64:
					while checksum_iteration < sequence:
						iteration_crc32 = zlibdll.crc32_combine(iteration_crc32, data_crc32[0], data_len)
						checksum_iteration += 1
				else:
					bit = 0
					bit_len = data_len
					iteration_crc32 = data_crc32[0]
					checksum_iteration = sequence
					while checksum_iteration:
						if checksum_iteration & 1:
							iteration_crc32 = zlibdll.crc32_combine(iteration_crc32, data_crc32[bit], bit_len)
						bit += 1
						bit_len <<= 1
						checksum_iteration >>= 1
					checksum_iteration = sequence
				xor_key |= xor_key << 16
				for i in range(checksums):
					checksum = struct.unpack_from('!I', data, 12 + i * 4)[0] ^ xor_key
					if checksum != iteration_crc32:
						checksum_queue.put_nowait((time.time(), '\n'.join([hex(packet_id), str(sequence), str(checksum_iteration), hex(checksum)[2:], hex(iteration_crc32)[2:], '\n'])))
					iteration_crc32 = zlibdll.crc32_combine(iteration_crc32, data_crc32[0], data_len)
					checksum_iteration += 1
				checksum_cache[packet_id] = checksum_iteration, iteration_crc32
			except KeyError:
				print '? ', hex(packet_id), sequence, hex(xor_key), checksums
			except rsa.pkcs1.VerificationError:
				# ugly, but i don't want to "unroll" rsa.verify in the try block
				keylength = rsa.common.byte_size(pub_key.n)
				encrypted = rsa.transform.bytes2int(signature)
				decrypted = rsa.core.decrypt_int(encrypted, pub_key.e, pub_key.n)
				clearsig = rsa.transform.int2bytes(decrypted, keylength)
				message_hash = rsa.compute_hash(message, 'SHA-256')
				signature_queue.put_nowait((time.time(), '\n'.join([hex(packet_id), str(sequence), clearsig[32:64].encode('hex'), message_hash.encode('hex'), '\n'])))
		except Queue.Empty:
			pass

signature_thread = threading.Thread(target=signature_thread_function)
signature_thread.start()

checksum_thread = threading.Thread(target=checksum_thread_function)
checksum_thread.start()

data_thread = threading.Thread(target=data_thread_function)
data_thread.start()

data_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
data_socket.bind(('127.0.0.1', port))

print 'ready'
while True:
	try:
		data_queue.put_nowait(data_socket.recv(4096))
	except KeyboardInterrupt:
		thread_function_event.set()
		break

data_thread.join()
checksum_thread.join()
signature_thread.join()
