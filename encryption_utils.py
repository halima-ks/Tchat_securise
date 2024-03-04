from nacl import public, encoding, secret
from nacl.utils import random as random_bytes

def generate_keypair():
    """
    Génère une paire de clés publique et privée pour le chiffrement.
    """
    private_key = public.PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key

def encrypt_message(private_key, public_key, message):
    """
    Chiffre un message avec la clé privée de l'expéditeur et la clé publique du destinataire.
    """
    box = public.Box(private_key, public_key)
    encrypted_message = box.encrypt(message.encode(), random_bytes(public.Box.NONCE_SIZE))
    return encrypted_message

def decrypt_message(private_key, public_key, encrypted_message):
    """
    Déchiffre un message avec la clé privée du destinataire et la clé publique de l'expéditeur.
    """
    box = public.Box(private_key, public_key)
    plaintext_message = box.decrypt(encrypted_message).decode()
    return plaintext_message

def encode_public_key(public_key):
    """
    Encode une clé publique pour l'envoi sur le réseau.
    """
    return public_key.encode(encoder=encoding.HexEncoder)

def decode_public_key(encoded_public_key):
    """
    Décodifie une clé publique reçue du réseau.
    """
    return public.PublicKey(encoded_public_key, encoder=encoding.HexEncoder)

