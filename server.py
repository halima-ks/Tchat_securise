import socket
import select
from nacl import public, encoding
from encryption_utils import generate_keypair, encrypt_message, decrypt_message, encode_public_key, decode_public_key


HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 5000

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((IP, PORT))
server_socket.listen()

# Liste des sockets pour la fonction select
sockets_list = [server_socket]

# Liste des clients connectés - socket comme clé, informations utilisateur comme données
clients = {}

# Messages à envoyer aux clients
messages_queue = {}

print(f'Ecoute des connexions sur {IP}:{PORT}...')

# Gère le message de la socket client
def receive_message(client_socket):
    try:
        message_header = client_socket.recv(HEADER_LENGTH)
        if not message_header:
            return False
        message_length = int(message_header.decode('utf-8').strip())
        return {'header': message_header, 'data': client_socket.recv(message_length)}
    except:
        return False

while True:
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)

    for notified_socket in read_sockets:
        if notified_socket == server_socket:
            client_socket, client_address = server_socket.accept()

            # Client vient de se connecter, nous attendons qu'il envoie son nom et clé publique
            user = receive_message(client_socket)
            if user is False:
                continue

            # Ajouter une socket acceptée à notre liste de sockets
            sockets_list.append(client_socket)

            # Sauvegarder le nom d'utilisateur et la clé publique
            clients[client_socket] = user
            messages_queue[client_socket] = []

            print('Nouvelle connexion acceptée de {}:{}, username: {}'.format(*client_address, user['data'].decode('utf-8')))

            # Envoyer la clé publique du serveur au client
            #server_public_key_encoded = encode_public_key(decode_public_key)
            #client_socket.send(server_public_key_encoded)
            # Décoder la clé publique
            # Recevoir la clé publique encodée du client
            public_key_encoded_length = client_socket.recv(HEADER_LENGTH)
            public_key_encoded = client_socket.recv(int(public_key_encoded_length.decode('utf-8').strip()))

            # Décoder la clé publique
            public_key = decode_public_key(public_key_encoded)

            # Encoder la clé publique
            server_public_key_encoded = encode_public_key(public_key)

            # Envoyer la clé publique encodée au client
            client_socket.send(server_public_key_encoded)

        else:
            # Recevoir le message
            message = receive_message(notified_socket)

            # Si False, le client s'est déconnecté, nettoyage
            if message is False:
                print('Connexion fermée de: {}'.format(clients[notified_socket]['data'].decode('utf-8')))
                sockets_list.remove(notified_socket)
                del clients[notified_socket]
                del messages_queue[notified_socket]
                continue

            # Récupérer la clé publique du client si ce n'est pas déjà fait
            if clients[notified_socket].get('public_key') is None:
                clients[notified_socket]['public_key'] = decode_public_key(message['data'])
                # Envoyer la clé publique du client à tous les autres clients
                for client_sock in clients:
                    if client_sock != notified_socket:  # ne pas envoyer la clé publique au client lui-même
                        messages_queue[client_sock].append(message)

            else:
                # Ajouter le message à la file d'attente des messages
                for client_sock in clients:
                    if client_sock != notified_socket:
                        messages_queue[client_sock].append(message)

            # Afficher le message
            user = clients[notified_socket]
            print(f'Message reçu de {user["data"].decode("utf-8")}: {message["data"].decode("utf-8")}')

    # Envoyer les messages en file d'attente
    for client_socket in messages_queue:
        for message_data in messages_queue[client_socket]:
            client_socket.send(message_data['header'] + message_data['data'])
        messages_queue[client_socket] = []

    # Gérer les exceptions socket
    for notified_socket in exception_sockets:
        sockets_list.remove(notified_socket)
        del clients[notified_socket]
        del messages_queue[notified_socket]

