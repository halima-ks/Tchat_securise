Halima Ksal
L3


# Introduction à la sécurité 


# Rapport de Projet 

# Titre : Chat sécurisé avec Pynacl


# Prérequis pour execution :

Il y a 3 fichiers server.py / client.py / encryption_utils.py

il est necessaire d'installer PyNaCl, elle peut etre installée via pip avec la commande : "pip install pynacl"

ouvrir un serveur : Python3 server.py
ouvrir client 1 : Python3 client.py
ouvrir client 2 : Python3 client.py 


# Résumé :
L'objectif principal de ce projet était de créer une application client - serveur capable d'échanger des messages de manière sécurisée. Le projet utilise les sockets TCP/IP pour la communication réseau et la bibliotheque PyNaCl pour le chiffrement basé sur les clés publiques/privées.


# Méthodologie :

Le projet a éte developpé en Python, en utilisant le module "socket" pour la communication réseau et "Pynacl" pour le chiffrement.


Le chiffrement dans ce projet est assuré par PyNaCl, une bibliothèque Python qui offre une interface aux primitives de cryptographie de libsodium, qui est elle-même une implémentation populaire de l'API NaCl (Networking and Cryptography library). NaCl fournit un ensemble d'opérations cryptographiques de haut niveau telles que le chiffrement à clé publique, le chiffrement symétrique, et la signature numérique.

Génération des clés Diffie-Hellman :
Le protocole Diffie-Hellman est utilisé pour échanger des clés de manière sécurisée sur un canal non sécurisé.L'un des principaux avantages de Diffie-Hellman est qu'il permet à deux parties de générer un secret partagé sans avoir eu de secret partagé préalable. Cependant, il ne fournit pas d'authentification par lui-même, donc il est souvent utilisé avec d'autres méthodes d'authentification pour assurer la sécurité contre les attaques de type "man-in-the-middle".


- Generation des clés : utilisation de PYnacl pour generer des paires de clés clients au serveur.

- Établir de la connexion : Utilisation des sockets TCP pour connecter les clients au serveur

- Échange de clés : Les clients échangent leurs clés publiques avec le serveur après la connexion 
(normalement je voulais faire l'echange de clef public + calcul pour avoir la clef privée)

- Chiffrement et Déchiffrement : Les messages sont chiffrés avec la clé publique du destinataire et déchiffrés avec la clé privée du destinataire

# Développement Server et Client :

1. Client :

- Genere des paires de clés à la connexion 
- Envoi sa clé publique au serveur 
- Reçoit et stocke la clé publique de l'autre client.
- Chiffre les messages avec la clé publiqque du destinataire avant l'envoi.
- Déchiffre les messages qui entre avec sa propre clé privée

2. Serveur :

- Écoute les connexions qui entre 
- Gere l'echange de clés publiques 
- C'est lui qui relaie les messages chiffrés entre les clients

"Encryption_utils" est une bibliotheque personnalisée qui a été créee pour fournir les fonctions utilitaires pour generer des paires de clés, chiffrer et dechiffrer des messages, et encoder/décoder des clés publiques pour le transfert sur le réseau.


# Premiere idee de conception : 
coté client :         
2 clients genere leur pairs 
envoyer leur clef public au serveur 
socket qui s'ouvre pour recevoir les donnée
2 socket une pour recevoir une pour envoyer 
calculer la clef privé du client avec la clef public de l'autre client 
dechiffre le message 


cote serveur : 

recevoir les 2 clefs public
stocker dans deux variables 
verifier le type 
apres avoir reçu les clès 
renvoyer les cles de la personne x à la personne y 
renvoi le message du client à l'autre sans le dechiffré


# Conclusion : 

PyNaCl est reconnue pour sa facilité d'utilisation et sa sécurité robuste. En conclusion, Pynacl s'est avéré être un bon choix pour ce projet, fournissant tous les outils nécessaires pour créer un système de chat sécurisé avec des garanties solides de confidentialité et d'intégrité des données. 


# Amelioration : 

Le code ne fonctionne pas car le serveur n'échange pas correctement les clés publiques entre les clients c'est en attente de la clef coté client.
Pour les ameliorations futurs, il pourrait être envisagé d'ajouter une interface utilisateur graphique, d'améliorer les protocoles de sécurité et d'implémenter des fonctionnalités supplémentaires on peut ajouter ssl par exemple pour securisé le serveur.

##################################################

j'ai quand meme mit le dossier de mon ancien code de chat qui n'était pas sécurisé car je dechiffrer dans le serveur. C'est le dossier "chat_ancien_version"