from nacl import public, encoding, secret

def generate_keypair():
    private_key = public.PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key

def encrypt_message(private_key, peer_public_key, message):
    box = public.Box(private_key, peer_public_key)
    encrypted = box.encrypt(message.encode('utf-8'))
    return encrypted

def decrypt_message(private_key, peer_public_key, encrypted_message):
    box = public.Box(private_key, peer_public_key)
    decrypted = box.decrypt(encrypted_message)
    return decrypted.decode('utf-8')

