import socket
import hashlib
from RSA import generate_key_pair, sign_message_digest, verify_message_digest, verify_certificate
from cryptography.hazmat.primitives import serialization
from X509 import build_certificate, certificate_from_pem, pem_from_cert

def generate_key_files():
    private_key, public_key = generate_key_pair()
    
    # Save private key and public key to a file
    with open('pki_private_key.pem', 'wb') as file:
        file.write(private_key)
    with open('pki_public_key.pem', 'wb') as file:
        file.write(public_key) 

    print("PKI's Private Key\n\n", private_key.decode())
    print("PKI's Public Key\n\n", public_key.decode())   


def issue_certificates():
    # Create a socket to listen for CSR requests
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('localhost', 8000))
        server_socket.listen(2)
        count = 0       #Temporary

        while True:
            # Accept connection from Tester or ECU
            client_socket, address = server_socket.accept()
            print(f'New connection from {address}\n')

            # Receive CSR from Tester or ECU
            csr_pem = client_socket.recv(4096)

            # Load PKI's private key
            with open('pki_private_key.pem', 'rb') as file:
                pki_private_key = serialization.load_pem_private_key(
                    file.read(),
                    password=None 
                )

            # Build and Sign the certificate using PKI's private key
            signed_certificate = build_certificate(csr_pem, pki_private_key)
            # Load PKI's public key
            with open('pki_public_key.pem', 'rb') as file:
                pki_public_key = file.read()

            # Send the signed certificate and PKI's public key to the requester
            client_socket.sendall(signed_certificate)
            client_socket.sendall(pki_public_key)
            print('Received valid CSR and Issued Certificate\n')

            # Save the issued certificate to a file
            with open('issued_certificates.pem', 'ab') as file:
                file.write(signed_certificate + b'\n')

            # Close the connection
            client_socket.close()
            count+=1            #Temporary
            if count == 2:
                print('Finished with issuing certificates for the day!')
                break

        server_socket.close()    


def verify_tester(auth_data):
    challenge = auth_data[0]
    signature = auth_data[1]
    tester_certificate = auth_data[2]
    message_digest = hashlib.sha512(challenge.encode('utf-8')).digest()

    # Load PKI's public key
    with open('pki_public_key.pem', 'rb') as file:
        pki_public_key = file.read()

    authentic_cert = verify_certificate(pki_public_key, tester_certificate)    

    if authentic_cert == True:
        # Load tester's public key from certificate
        tester_public_key = certificate_from_pem(tester_certificate).public_key().public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )

        # Verify the signed response using tester's public key
        response_digest = verify_message_digest(tester_public_key, message_digest, signature)

        if response_digest == True:
            print('Tester Authentication Successfull\n')
            # Load PKI's private key
            with open('pki_private_key.pem', 'rb') as file:
                pki_private_key = file.read()
            # Sign the message digest using PKI's private key
            signature = sign_message_digest(pki_private_key, message_digest)
            # Send the signed response to the tester
            return signature
        else:
            print('Warning: Unverified Tester\n')

            
if __name__ == '__main__':
    # Generate key files
    generate_key_files()

    # Issue certificates
    issue_certificates()

    # Listen for access requests and authenticate Tester
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('localhost', 8000))
        server_socket.listen(2)

        while True:
            # Accept connection from Tester
            client_socket, address = server_socket.accept()
            print(f'New connection from {address}\n')

            # Receive challenge string and tester's certificate
            challenge = client_socket.recv(256)
            signature = client_socket.recv(256)
            tester_certificate = client_socket.recv(2048)
            auth_data = (challenge.decode('utf-8'), signature, tester_certificate)
            print("Received data for Tester's authentication\n")

            # Verify the tester
            signature = verify_tester(auth_data)
            client_socket.sendall(signature)

            # Close the connection
            client_socket.close()