import hashlib
import os
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
        return Block(0, str(datetime.datetime.now()), "Genesis Block", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        latest_block = self.get_latest_block()
        new_block = Block(
            index=latest_block.index + 1,
            timestamp=str(datetime.datetime.now()),
            data=data,
            previous_hash=latest_block.hash
        )
        self.chain.append(new_block)

    def calculate_hash(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            return hashlib.sha256(content).hexdigest()
        except Exception:
            return None

    def is_block_tampered(self, block):
        file_path = f'encrypted/{block.data}.enc'
        if not os.path.exists(file_path):
            return True  # File missing = tampered

        with open(file_path, 'rb') as f:
            file_data = f.read()

        current_file_hash = hashlib.sha256(file_data).hexdigest()
        return current_file_hash != block.hash

    def verify_chain(self):
        verified = []
        for i, block in enumerate(self.chain):
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
