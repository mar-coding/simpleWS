import binascii
import hashlib
import secrets

from Crypto.Cipher import AES
from tinyec import registry

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()


def encrypt_ECC(msg, pubKey,curve):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

def get_private_key():
    """
    It will create private key based on ECC-AES Algorithm

    Returns:
        private_key,curve => in list format
    """
    curve = registry.get_curve('brainpoolP256r1')
    privKey = secrets.randbelow(curve.field.n)
    return privKey,curve

def get_public_key(pr_key,curve):
    """
    It will take private_key and curve and return
    public_key

    Returns:
        public_key
    """
    pubKey = pr_key * curve.g
    return pubKey

if __name__ == '__main__':
    #pubKey * ciphertextPrivKey = ciphertextPubKey * privKey
    msg = b'This is a Test msg!'
    print("original msg:", msg)
    print()
    privKey,curve = get_private_key()
    pubKey = get_public_key(privKey,curve)
    print("private key:", privKey)
    print()
    print("public key:", pubKey)
    encryptedMsg = encrypt_ECC(msg, pubKey)
    decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
    print("decrypted msg:", decryptedMsg)