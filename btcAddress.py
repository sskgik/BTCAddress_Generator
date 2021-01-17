#cording : utf-8
#Sample:https://qiita.com/kaz1shuu2/items/921dcbebb7fbea14f085

import ecdsa
import secrets
import hashlib
import base58

class Generater:
    def __init__(self):
        p = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 -2 ** 7 - 2 ** 6 - 2 ** 4 -1
        PrivKey = self.new_privatekey(p)
        PubKey  = self.new_pubkey(PrivKey)
        address = self.new_address(bytes.fromhex("00"),PubKey)
    
    def new_privatekey(self,p):
        Privkey = secrets.randbelow(p)
        Privkey = format(Privkey,"x").zfill(64) 
        print("\nPrivatekey = " + Privkey)
        return Privkey
    
    def new_pubkey(self,privatekey):
        bin_privkey = bytes.fromhex(privatekey)
        signing_key = ecdsa.SigningKey.from_string(bin_privkey,curve = ecdsa.SECP256k1)
        verifying_key = signing_key.get_verifying_key()
        PubKey = bytes.fromhex("04")+verifying_key.to_string()
        PubKey = PubKey.hex()
        print("Publickey = " + PubKey)
        return PubKey
    
    def new_address(self,version,publickey):
        ba = bytes.fromhex(publickey)
        digest = hashlib.sha256(ba).digest()
        new_digest = hashlib.new('ripemd160')
        new_digest.update(digest)
        pubkey_hash = new_digest.digest()

        pre_address = version + pubkey_hash
        address = hashlib.sha256(pre_address).digest()
        address = hashlib.sha256(address).digest()
        checksum = address[:4]
        address = pre_address + checksum
        address = base58.b58encode(address)
        address = address.decode()
        print("Address = " + address + "\n")
        return address

address = Generater()


