import rsa
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--public_key', required=True, help='public key file')
parser.add_argument('-r', '--private_key', required=True, help='private key file')
args = parser.parse_args()

(public_key, private_key) = rsa.newkeys(512)

key_data = ''
n = public_key.n
for _ in range(64):
	key_data = chr(n & 0xff) + key_data
	n >>= 8
e = public_key.e
while e:
	key_data += chr(e & 0xff)
	e >>= 8
with open(args.public_key, 'w') as _:
	_.write(key_data)

with open(args.private_key, 'w') as _:
	_.write(private_key.save_pkcs1())
