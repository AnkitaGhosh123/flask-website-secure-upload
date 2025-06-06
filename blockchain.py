import hashlib
import time

class Block:
    def __init__(self, index, data, prev_hash):
        self.index = index
        self.timestamp = time.time()
        self.data = data
        self.prev_hash = prev_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self, filepath):
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        return hashlib.sha256(content).hexdigest()
    except Exception:
        return None

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, "Genesis Block", "0")

    def add_block(self, block):
        if block.prev_hash == self.chain[-1].hash:
            self.chain.append(block)
