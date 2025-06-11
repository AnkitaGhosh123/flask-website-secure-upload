import hashlib
import datetime

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        value = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}"
        return hashlib.sha256(value.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, str(datetime.datetime.utcnow()), "Genesis Block", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, block):
        self.chain.append(block)

    def verify_chain(self):
        verified = []
        for i, block in enumerate(self.chain):
            valid_hash = block.calculate_hash()
            valid_prev = (i == 0) or (block.previous_hash == self.chain[i - 1].hash)

            verified.append({
                'index': block.index,
                'timestamp': block.timestamp,
                'data': block.data,
                'prev_hash': block.previous_hash,
                'hash': block.hash,
                'valid': (block.hash == valid_hash and valid_prev)
            })

        return verified
