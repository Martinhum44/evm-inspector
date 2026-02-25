import tkinter as tk
import requests
import json
from Crypto.Hash import keccak
import argparse
import reference

parser = argparse.ArgumentParser(description="My first CLI")

class Bytes32:
    def __init__(self, _bytes):
        if type(_bytes) is not bytes:
            raise TypeError("_bytes must be type bytes")
        if len(_bytes) != 32:
            raise ValueError(f"A bytes32 object must be 32 bytes long, not {len(_bytes)}")
        self.bytes = _bytes
    
    @staticmethod
    def load_from_int(x):
        if x > 2**256 - 1:
            raise OverflowError("x to large for 256 bits")
        
        b = int.to_bytes(x, 32, "big")
        return Bytes32(b)
    
    @staticmethod
    def load_from_string(x):
        if type(x) is not str:
            raise TypeError("x must be string")
        return Bytes32(x.encode().rjust(32, b"\x00"))


    @staticmethod
    def load_from_bytes(x):
        if not isinstance(x, (bytes, bytearray)):
            raise TypeError("x must be bytes-like")
        
        if len(x) > 32:
            raise ValueError("x to long")

        padded_b = x.rjust(32, b"\x00")
        return Bytes32(padded_b)

    @staticmethod
    def keccak256(*args):
        k = keccak.new(digest_bits=256)
        for arg in args:
            if len(arg) != 32:
                raise ValueError(f"Every item must be 32 bytes, not {len(arg)}.")
        
        _sum = b""
        for arg in args:
            _sum += bytes(arg)
        
        k.update(_sum)
        return k.digest()
    
    @staticmethod
    def load_from_hex(x):
        if x.startswith("0x"):
            x = x[2:]
        b = bytes.fromhex(x)
        return Bytes32(b.rjust(32, b"\x00"))
    
    def __int__(self):
        return int.from_bytes(self.bytes, "big")

    def __bytes__(self):
        return self.bytes

    def __len__(self):
        return 32
    
    def __getitem__(self, index):
        if isinstance(index, slice):
            return self.bytes[index.start : index.stop : index.step]
        return self.bytes[index]
    
    def __eq__(self, other):
        if not isinstance(other, Bytes32):
            raise NotImplemented
        return self.bytes == other.bytes
    
    def __repr__(self):
        return "Bytes32 object: " +self.bytes.hex()
    
    def hex(self):
        return self.bytes.hex()

def check_var(var, key, default):
    try:
        return var[key]
    except KeyError:
        return default

def get_value_at_storage(rpc_provider, address, slot, **kwargs):
    type_of_var = check_var(kwargs, "type", "basic")

    if type_of_var == "mapping":
        if type(kwargs["key"]) is int:
            key = Bytes32.load_from_int(kwargs["key"])
        elif type(kwargs["key"]) is bytes:
            key = Bytes32.load_from_bytes(kwargs["key"])
        elif type(kwargs["key"]) is str:
            key = Bytes32.load_from_string(kwargs["key"])
        else:
            raise TypeError(f"Type of key must be int, str or bytes not {type(kwargs['key'])}")
        slot_32 = Bytes32.load_from_int(slot)
        slot_to_read_from = Bytes32.keccak256(key, slot_32)
    elif type_of_var == "array":
        index = Bytes32.load_from_int(kwargs["index"])
        slot_32 = Bytes32.load_from_int(slot)
        hashed_slot = Bytes32.keccak256(slot_32)
        slot_to_read_from = Bytes32.load_from_int(int.from_bytes(hashed_slot, "big") + index)
    else:
        slot_to_read_from = Bytes32.load_from_int(slot)
    print("slot:",slot_to_read_from.hex())


    RPC_URL = rpc_provider

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getStorageAt",
        "params": [
            address,
            slot_to_read_from.hex(),
            "latest"
        ]
    }

    res = requests.post(RPC_URL, json=payload)
    data = res.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    return (res.json()["result"])

#bytes_object = Bytes32.load_from_hex(get_value_at_storage("https://mainnet.infura.io/v3/dd1a1dee389540579bd4d6c7be152898","0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 3, type="mapping", key=bytes.fromhex("6b44ba0a126a2A1a8aa6cD1AdeeD002e141Bcd44")))
#print(bytes_object)

def decode(byte, to):
    if to == "int":
        return int.from_bytes(byte, "big")
    if to == "string":
        return byte.decode()
    if to == "hex":
        return byte.hex()
    return byte

def determine_decoding_from_type(type):
    if type.startswith("uint") or type.startswith("int"):
        return "int"
    if type == "string":
        return "string"
    if type == "address" or type.startswith("bytes"):
        return "hex"

parser.add_argument("rpc", help="Your RPC provider")
parser.add_argument("address", help="The address of the contract you want to inspect.")
parser.add_argument(
    "--type",
    choices=["basic", "mapping", "array"],
    default="basic"
)
parser.add_argument("--slot", type=int, required=True)
parser.add_argument("--index", type=int)
parser.add_argument("--key")

parser.add_argument(
    "--decode",
    choices=["int", "bytes", "hex", "string"],
    default="bytes"
)

parser.add_argument(
    "--unpack",
)

def ignore_not_exists(value, attribute):
    return getattr(value, attribute, None)
    
args = parser.parse_args()
try:
    if ignore_not_exists(args, "key")[:2] == "0x":
        key = bytes.fromhex(ignore_not_exists(args, "key")[2:])
    else:
        key = ignore_not_exists(args, "key")
except Exception as e:
    key = ignore_not_exists(args, "key")

val = get_value_at_storage(args.rpc, args.address, args.slot, type=ignore_not_exists(args,"type"), index=ignore_not_exists(args,"index"), key=key)[2:]
value = bytes(Bytes32.load_from_hex(val))

if ignore_not_exists(args, "unpack") != None:
    unpackings = args.unpack.split(",")
    unpackings = [i.strip() for i in unpackings]
    bytes_unpackings = [0]

    try:
        total = 0
        for i in unpackings:
            total += int(reference.SOLIDITY_TYPE_SIZES[i])
            bytes_unpackings.append(total)
    except KeyError as e:
        print(f"{e} is not a data type")      
    else:
        if total != 32:
            print(f"Total of unpackings must be 32, not {total}")
        else:
            for index, item in enumerate(bytes_unpackings):
                if index != len(bytes_unpackings) - 1:
                    print(f"{unpackings[index]}: {decode(value[item : bytes_unpackings[index+1]], determine_decoding_from_type(unpackings[index]))}")
        
else:
    print(f"Value at slot {args.slot}:")
    if ignore_not_exists(args, "key") != None:
        print(f"key {args.key}:")

    try:
        print(decode(value, args.decode))
    except Exception as e:
        print(f"Error: {e}")