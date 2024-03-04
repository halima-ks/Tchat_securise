import socket
import select
import errno
import sys
from nacl import public, encoding
from encryption_utils import generate_keypair, encrypt_message, decrypt_message

HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 1234

# Générer la paire de clés Diffie-Hellman du client
private_key, public_key = generate_keypair()

my_username = input("Username: ")
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((IP, PORT))
client_socket.setblocking(False)

username = my_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)

public_key_encoded = public_key.encode(encoder=encoding.HexEncoder)
client_socket.send(f"{len(public_key_encoded):<{HEADER_LENGTH}}".encode('utf-8') + public_key_encoded)

# Initialiser la variable pour stocker la clé publique du serveur
server_public_key = None

while True:
    message = input(f"{my_username} > ")
    
    # Si la clé publique du serveur n'a pas encore été reçue, ne pas envoyer de messages
    if server_public_key and message:
        encrypted_message = encrypt_message(private_key, server_public_key, message)
        message_header = f"{len(encrypted_message):<{HEADER_LENGTH}}".encode('utf-8')
        client_socket.send(message_header + encrypted_message)

    try:
        # Tenter de recevoir des données du serveur
        while True:
            # Si la clé publique du serveur n'a pas été reçue, essayez de la recevoir
            if not server_public_key:
                server_public_key_encoded_length = client_socket.recv(HEADER_LENGTH)
                if not server_public_key_encoded_length:
                    print('Connection closed by the server')
                    sys.exit()
                server_public_key_length = int(server_public_key_encoded_length.decode('utf-8').strip())
                server_public_key_encoded = client_socket.recv(server_public_key_length)
                server_public_key = public.PublicKey(server_public_key_encoded, encoder=encoding.HexEncoder)
            else:
                # Réception de l'en-tête contenant la longueur du nom d'utilisateur
                username_header = client_socket.recv(HEADER_LENGTH)
                if not len(username_header):
                    print('Connection closed by the server')
                    sys.exit()

                username_length = int(username_header.decode('utf-8').strip())
                username = client_socket.recv(username_length).decode('utf-8')

                # Réception de l'en-tête contenant la longueur du message chiffré
                message_header = client_socket.recv(HEADER_LENGTH)
                message_length = int(message_header.decode('utf-8').strip())
                encrypted_message = client_socket.recv(message_length)
                
                # Déchiffrer le message reçu
                message = decrypt_message(private_key, server_public_key, encrypted_message)
                print(f"{username} > {message}")

    except IOError as e:
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print('Reading error: {}'.format(str(e)))
            sys.exit()
        # En mode non bloquant, si aucune donnée n'est disponible, continuer la boucle
        continue

    except Exception as e:
        print('General error: {}'.format(str(e)))
        sys.exit()

