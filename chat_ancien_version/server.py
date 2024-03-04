import socket
import select
from nacl import public, encoding, secret
from encryption_utils import generate_keypair, encrypt_message, decrypt_message

HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 1234

# Générer la paire de clés Diffie-Hellman du serveur
server_private_key, server_public_key = generate_keypair()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((IP, PORT))
server_socket.listen()

sockets_list = [server_socket]
clients = {}
client_public_keys = {}

print(f"Listening for connections on {IP}:{PORT}...")

def receive_message(client_socket):
    try:
        message_header = client_socket.recv(HEADER_LENGTH)

        if not len(message_header):
            return False

        message_length = int(message_header.decode('utf-8').strip())
        return {"header": message_header, "data": client_socket.recv(message_length)}

    except:
        return False

while True:
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)

    for notified_socket in read_sockets:
        if notified_socket == server_socket:
            client_socket, client_address = server_socket.accept()
            
            # Envoie de la clé publique du serveur au client
            public_key_encoded = server_public_key.encode(encoder=encoding.HexEncoder)
            client_socket.send(f"{len(public_key_encoded):<{HEADER_LENGTH}}".encode('utf-8') + public_key_encoded)

            user = receive_message(client_socket)
            if user is False:
                continue

            # Recevoir la clé publique du client
            client_public_key_encoded = receive_message(client_socket)
            if client_public_key_encoded is False:
                continue

            client_public_key = public.PublicKey(client_public_key_encoded['data'], encoder=encoding.HexEncoder)
            client_public_keys[client_socket] = client_public_key

            sockets_list.append(client_socket)
            clients[client_socket] = user

            print('Accepted new connection from {}:{}, username: {}'.format(*client_address, user['data'].decode('utf-8')))

        else:
            message = receive_message(notified_socket)

            if message is False:
                print('Closed connection from: {}'.format(clients[notified_socket]['data'].decode('utf-8')))
                sockets_list.remove(notified_socket)
                del clients[notified_socket]
                continue

            user = clients[notified_socket]
            print(f"Received message from {user['data'].decode('utf-8')}: {message['data']}")

            # Déchiffrer le message reçu avec la clé privée du serveur
            decrypted_message = decrypt_message(server_private_key, client_public_keys[notified_socket], message['data'])

            for client_socket in clients:
                if client_socket != notified_socket:
                    # Chiffrer le message pour chaque client à l'aide de leur clé publique respective
                    encrypted_message_for_client = encrypt_message(server_private_key, client_public_keys[client_socket], decrypted_message)
                    
                    # Envoyer le message chiffré au client
                    client_socket.send(user['header'] + user['data'] + message['header'] + encrypted_message_for_client)

    for notified_socket in exception_sockets:
        sockets_list.remove(notified_socket)
        del clients[notified_socket]

