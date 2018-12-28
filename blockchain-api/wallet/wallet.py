import externalmodules.mnemonic as mn
import hashlib, hmac, base58
from fastecdsa import keys, curve

"""
ref: 
http://lenschulwitz.com/base58
https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
"""

"""Generate wallet address for a user. Check if the address already exists before in the wallet database
before returning the address to the user."""

WALLET_DATABASE = set()


def generate_wallet_address(passphrase=''):
    """
    :param passphrase: salt for the mnemonic
    The optional passphrase creates two important features:
    • A second factor (something memorized) that makes a mnemonic useless on its
    own, protecting mnemonic backups from compromise by a thief.
    • A form of plausible deniability or “duress wallet,” where a chosen passphrase
    leads to a wallet with a small amount of funds used to distract an attacker from
    the “real” wallet that contains the majority of funds.
    However, it is important to note that the use of a passphrase also introduces the risk
    of loss:
    • If the wallet owner is incapacitated or dead and no one else knows the pass‐
    phrase, the seed is useless and all the funds stored in the wallet are lost forever.
    • Conversely, if the owner backs up the passphrase in the same place as the seed, it
    defeats the purpose of a second factor.

    :return: (master)private key/address, (master)public key/address, (master) chain code, mnemonic,
    passphrase
    """

    flag = True

    while flag:
        m = mn.Mnemonic('english')
        mnemonic = m.generate()
        seed = m.to_seed(mnemonic, passphrase)

        # 64 bytes = 512 bits
        hash_512 = hmac.new(key=seed, digestmod=hashlib.sha512).digest()

        priv_key = hash_512[:32]

        # get the public key corresponding to the private key we just generated
        pub_key = keys.get_public_key(int.from_bytes(priv_key, byteorder='little'), curve.P256)

        x = int.to_bytes(pub_key.x, 32, byteorder='little')
        y = int.to_bytes(pub_key.y, 32, byteorder='little')

        # got to check the endianness of the bytes
        bitcoin_wallet_address = _generate_wallet_address(x+y)

        chain_code = hash_512[32:]

        # check if this public key already exists
        if bitcoin_wallet_address not in WALLET_DATABASE:
            # add this public key to the database
            WALLET_DATABASE.add(bitcoin_wallet_address)
            flag = False

    """A bitcoin address is not the same as a public key. Bitcoin addresses
    are derived from a public key using a one-way function.
    len(seed) = 64 bytes """
    return priv_key, bitcoin_wallet_address, chain_code, mnemonic, seed.hex(), passphrase


def double_sha256(inp):
    return hashlib.sha256(hashlib.sha256(inp).digest()).digest()


def _generate_wallet_address(pub_key):
    h = hashlib.new('ripemd160')
    h.update(double_sha256(pub_key))
    pub_key_hash = h.digest().hex()

    print("pub key", pub_key_hash, len(pub_key_hash))

    # Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
    ext_ripemd160_ver_byte = "00" + pub_key_hash

    # ================ Base58Check encoding ==================
    bitcoin_address = _base58_check_encoding(ext_ripemd160_ver_byte)
    print(bitcoin_address, len(bitcoin_address))
    return bitcoin_address


def _base58_check_encoding(ext_ripemd160_ver_byte):
    # Perform double SHA-256 hash
    res = double_sha256(ext_ripemd160_ver_byte.encode('ascii')).hex()
    print(len(res))

    # Take the first 4 bytes of the second SHA-256 hash. This is the address checksum
    address_checksum = res[:8]

    # Add the 4 checksum bytes from previous step at the end of extended RIPEMD-160 hash.
    # This is the 25-byte binary Bitcoin Address. 21 + 4 bytes
    binary_bitcoin_address = ext_ripemd160_ver_byte + address_checksum
    print("42 char", len(ext_ripemd160_ver_byte))
    print("50 char", len(binary_bitcoin_address), binary_bitcoin_address)

    # Convert the result from a byte string into a base58 string using Base58Check encoding.
    return base58.b58encode(bytes.fromhex(binary_bitcoin_address))


print(generate_wallet_address(passphrase="blockchain"))
