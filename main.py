import socket
import json
import hashlib
import binascii
import random

from pprint import pprint

def get_random_nonce():
    return hex(random.randint(0, 2**32 - 1))[2:].zfill(8)

def connect_to_pool(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock

def subscribe_to_mining(sock):
    sock.sendall(b'{"id": 1, "method": "mining.subscribe", "params": []}\n')
    lines = sock.recv(1024).decode().split('\n')
    response = json.loads(lines[0])
    return response['result']

def authorize_worker(sock, address):
    sock.sendall(b'{"params": ["'+address.encode()+b'", "password"], "id": 2, "method": "mining.authorize"}\n')

def wait_for_mining_notify(sock):
    response = b''
    while response.count(b'\n') < 4 and b'mining.notify' not in response:
        response += sock.recv(1024)
    return response

def parse_mining_notify(response):
    return [json.loads(res) for res in response.decode().split('\n') if len(res.strip()) > 0 and 'mining.notify' in res]

def calculate_target(nbits):
    target = (nbits[2:] + '00' * (int(nbits[:2], 16) - 3)).zfill(64)
    return target

def calculate_merkle_root(coinb1, extranonce1, extranonce2, coinb2, merkle_branch):
    coinbase = coinb1 + extranonce1 + extranonce2 + coinb2
    coinbase_hash_bin = hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbase)).digest()).digest()

    merkle_root = coinbase_hash_bin
    for h in merkle_branch:
        merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + binascii.unhexlify(h)).digest()).digest()

    merkle_root = binascii.hexlify(merkle_root).decode()

    merkle_root = ''.join([merkle_root[i] + merkle_root[i + 1] for i in range(0, len(merkle_root), 2)][::-1])

    return merkle_root

def construct_blockheader(version, prevhash, merkle_root, nbits, ntime, nonce):
    blockheader = version + prevhash + merkle_root + nbits + ntime + nonce + \
        '000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000'
    return blockheader

def calculate_block_hash(blockheader):
    hash = hashlib.sha256(hashlib.sha256(binascii.unhexlify(blockheader)).digest()).digest()
    hash = binascii.hexlify(hash).decode()
    return hash

def main():
    address = 'BTC_ADRESS_HERE'
    nonce = get_random_nonce()
    host = 'solo.ckpool.org'
    port = 3333

    # print("address: {} nonce: {}".format(address, nonce))
    # print("host: {} port: {}".format(host, port))

    sock = connect_to_pool(host, port)

    sub_details, extranonce1, extranonce2_size = subscribe_to_mining(sock)
    authorize_worker(sock, address)

    response = wait_for_mining_notify(sock)
    responses = parse_mining_notify(response)
    # pprint(responses)

    job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs = responses[0]['params']

    target = calculate_target(nbits)
    # print('nbits: {} target: {}\n'.format(nbits, target))

    extranonce2 = '00' * extranonce2_size
    merkle_root = calculate_merkle_root(coinb1, extranonce1, extranonce2, coinb2, merkle_branch)
    # print('merkle_root: {}\n'.format(merkle_root))

    blockheader = construct_blockheader(version, prevhash, merkle_root, nbits, ntime, nonce)
    # print('blockheader:\n{}\n'.format(blockheader))

    block_hash = calculate_block_hash(blockheader)
    # print('hash: {}'.format(block_hash))

    if block_hash < target:
        # print('success!!')
        payload = '{"params": ["'+address+'", "'+job_id+'", "'+extranonce2 \
            +'", "'+ntime+'", "'+nonce+'"], "id": 1, "method": "mining.submit"}\n'
        sock.sendall(payload.encode())
        # print(sock.recv(1024))
    else:
        # print('failed mine, hash is greater than target')
        pass

    sock.close()

if __name__ == "__main__":
    main()
