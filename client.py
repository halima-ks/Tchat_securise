import socket
import threading
import sys
from nacl import public, encoding
from encryption_utils import generate_keypair, encrypt_message, decrypt_message, encode_public_key, decode_public_key

HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 5000

# Générer la paire de clés Diffie-Hellman du client
private_key, public_key = generate_keypair()

# Demander le nom d'utilisateur
my_username = input("Username: ")

# Créer deux sockets : une pour l'envoi et une pour la réception
send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
receive_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Se connecter au serveur avec les deux sockets
send_socket.connect((IP, PORT))
receive_socket.connect((IP, PORT))

# Envoyer le nom d'utilisateur et la clé publique au serveur via la socket d'envoi
username_encoded = my_username.encode('utf-8')
username_header = f"{len(username_encoded):<{HEADER_LENGTH}}".encode('utf-8')
send_socket.send(username_header + username_encoded)

public_key_encoded = encode_public_key(public_key)
send_socket.send(f"{len(public_key_encoded):<{HEADER_LENGTH}}".encode('utf-8') + public_key_encoded)

# Fonction pour gérer l'envoi de messages
def send_messages(send_sock, my_private_key, other_client_public_key):
    while True:
        message = input(f"{my_username} > ")
        if message:
            encrypted_message = encrypt_message(my_private_key, other_client_public_key, message)
            message_header = f"{len(encrypted_message):<{HEADER_LENGTH}}".encode('utf-8')
            send_sock.send(message_header + encrypted_message)

# Fonction pour gérer la réception de messages
def receive_messages(receive_sock, my_private_key):
    while True:
        try:
            # Réception de la clé publique de l'autre client du serveur
            other_client_public_key_encoded_length = receive_sock.recv(HEADER_LENGTH)
            other_client_public_key_length = int(other_client_public_key_encoded_length.decode('utf-8').strip())
            other_client_public_key_encoded = receive_sock.recv(other_client_public_key_length)
            other_client_public_key = decode_public_key(other_client_public_key_encoded)
            
            # Réception de messages
            username_header = receive_sock.recv(HEADER_LENGTH)
            username_length = int(username_header.decode('utf-8').strip())
            username = receive_sock.recv(username_length).decode('utf-8')
            
            message_header = receive_sock.recv(HEADER_LENGTH)
            message_length = int(message_header.decode('utf-8').strip())
            encrypted_message = receive_sock.recv(message_length)
            
            # Déchiffrer le message reçu
            message = decrypt_message(my_private_key, other_client_public_key, encrypted_message)
            print(f"{username} > {message}")

        except IOError as e:
            print('Reading error:', str(e))
        except Exception as e:
            print("General error: ", str(e))
            receive_sock.close()
            break

# Recevoir la clé publique de l'autre client du serveur via la socket de réception
try:
    print("Attente de la clé publique de l'autre client...")
    other_client_public_key_encoded_length = receive_socket.recv(HEADER_LENGTH)
    if not other_client_public_key_encoded_length:
        print('Connexion fermée par le serveur.')
        sys.exit()

    other_client_public_key_length = int(other_client_public_key_encoded_length.decode('utf-8').strip())
    other_client_public_key_encoded = receive_socket.recv(other_client_public_key_length)
    other_client_public_key = decode_public_key(other_client_public_key_encoded)
    print("Reçu la clé publique de l'autre client")
except Exception as e:
    print(f"Erreur de réception de la clé publique de l'autre client : {e}")
    sys.exit()

# Démarrer les threads pour l'envoi et la réception de messages
send_thread = threading.Thread(target=send_messages, args=(send_socket, private_key, other_client_public_key))
receive_thread = threading.Thread(target=receive_messages, args=(receive_socket, private_key))

send_thread.start()
receive_thread.start()

send_thread.join()
receive_thread.join()

send_socket.close()
receive_socket.close()

