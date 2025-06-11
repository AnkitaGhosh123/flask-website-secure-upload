import hashlib
import os
import datetime

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data  # this should be the encrypted filename
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        value = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}"
        return hashlib.sha256(value.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, str(datetime.datetime.now()), "Genesis Block", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, block):
        self.chain.append(block)

    def calculate_file_hash(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            return hashlib.sha256(content).hexdigest()
        except Exception:
            return None

    def is_block_tampered(self, block):
        # Assumes encrypted filename is stored in block.data
        file_path = os.path.join('encrypted', block.data)
        if not os.path.exists(file_path):
            return True  # File missing = tampered

        file_hash = self.calculate_file_hash(file_path)
        return file_hash != self.hash_from_block_data(block)

    def hash_from_block_data(self, block):
        # To simulate block verification via its original structure
        value = f"{block.index}{block.timestamp}{block.data}{block.previous_hash}"
        return hashlib.sha256(value.encode()).hexdigest()

    def verify_chain(self):
        verified = []
        for block in self.chain:
            tampered = self.is_block_tampered(block)
            verified.append({
                'index': block.index,
                'timestamp': block.timestamp,
                'data': block.data,
                'prev_hash': block.previous_hash,
                'hash': block.hash,
                'tampered': tampered
            })
        return verified
