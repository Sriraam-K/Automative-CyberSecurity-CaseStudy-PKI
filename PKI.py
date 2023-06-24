import socket
import hashlib
from IPv4_Ports import *
from RSA import generate_key_pair, sign_message_digest, verify_message_digest, verify_certificate
from cryptography.hazmat.primitives import serialization
from X509 import build_certificate, certificate_from_pem, pem_from_cert

class PKI:
    def __init__(self):
        self.PR_pki = None
        self.PU_pki = None
        self.Issued_certificates = []

    
    def generate_key_files(self):
        self.PR_pki, self.PU_pki = generate_key_pair()
        
        # Save private key and public key to a file
        with open('pki_private_key.pem', 'wb') as file:
            file.write(self.PR_pki)
        with open('pki_public_key.pem', 'wb') as file:
            file.write(self.PU_pki) 

        print("PKI's Private Key\n\n", self.PR_pki.decode())
        print("PKI's Public Key\n\n", self.PU_pki.decode())


    def load_resources(self):
        try:
            # Load PKI's private key
            with open('pki_private_key.pem', 'rb') as file:
                self.PR_pki = file.read()
            # Load PKI's public key
            with open('pki_public_key.pem', 'rb') as file:
                self.PU_pki = file.read()
            # Load Issued digital certificates
            with open('issued_certificates.pem', 'rb') as file:
                lines = file.readlines()
                current_cert = b''
                for line in lines:
                    if line.strip():  # Skip empty lines
                        current_cert += line
                        if line.startswith(b'-----END CERTIFICATE-----'):
                            self.Issued_certificates.append(current_cert)
                            current_cert = b''

            print('All resources loaded successfully and PKI server ready to run....')
        except:
            print('No resources found: Keys generating....')
            self.generate_key_files() 


    def issue_certificates(self, client_socket):
        # Receive CSR from Tester or ECU
        csr_pem = client_socket.recv(4096)

        # Create a digital certificate for CSR received
        signed_certificate = build_certificate(csr_pem, self.PR_pki)

        # Send the signed certificate and PKI's public key to the requester
        client_socket.sendall(signed_certificate)
        client_socket.sendall(self.PU_pki)
        print('Received valid CSR and Issued Certificate\n')

        # Save the issued certificate to a file
        with open('issued_certificates.pem', 'ab') as file:
            file.write(signed_certificate + b'\n')

        self.Issued_certificates.append(signed_certificate)

    
    def one_step_authentication(self, client_socket):
        credentials = {}
        with open("user_credentials.txt", "r") as file:
            for line in file:
                username, password = line.strip().split(":")
                credentials[username] = password

        # Receive username and password from User 
        client_socket.send(b'Enter Username:')
        username = client_socket.recv(5).decode()
        client_socket.send(b'Enter Password:')
        password = client_socket.recv(8).decode()

        # Validate the credentials
        if username in credentials and credentials[username] == password:
            print('1st step Authentication Successful!')
            client_socket.send(b'1st step Authentication Successful!!\n')
            return True
        
        else:
            print('1st step Authentication Failed.....Aborting connection!\n')
            client_socket.send(b'1st step Authentication Failed......')
            return False
                   

    def two_step_authentication(self, client_socket):

        if self.one_step_authentication(client_socket) == True:
            client_socket.sendall(b'Send Details for 2nd step Authentication')
            challenge = client_socket.recv(256).decode('utf-8')
            signature = client_socket.recv(256)
            tester_certificate_pem = client_socket.recv(2048)
            message_digest = hashlib.sha512(challenge.encode('utf-8')).digest()

            print("Received data for Tester's 2nd step authentication\n")

            authentic_cert = verify_certificate(self.PU_pki, tester_certificate_pem)    

            if authentic_cert == True:
                # Load tester's public key from certificate
                tester_public_key = certificate_from_pem(tester_certificate_pem).public_key().public_bytes(
                                        encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                                    )

                # Verify the signed response using tester's public key
                response_digest = verify_message_digest(tester_public_key, message_digest, signature)

                if response_digest == True:
                    print('Tester Authentication Successfull\n')
                    # Sign the message digest using PKI's private key
                    signature = sign_message_digest(self.PR_pki, message_digest)
                    # Send the signed response to the tester
                    return signature
                else:
                    print('Warning: Unverified Tester\n')

        return b'fail'

            
if __name__ == '__main__':
    Trust = PKI()

    # Load PKI resources once it starts  
    Trust.load_resources()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((PKI_HOST, PKI_PORT))
        server_socket.listen(2)

        while True:
            # Accept connection from Tester
            client_socket, address = server_socket.accept()
            print(f'New connection from {address}\n')

            service_request = client_socket.recv(2).decode()

            match service_request:
                case 'IC': # Issue Digital Certificate
                    Trust.issue_certificates(client_socket)

                case 'VT': # Verify/Authenticate Tester
                    # Verify the tester
                    signature = Trust.two_step_authentication(client_socket)
                    # if signature != b'fail':
                    client_socket.sendall(signature)

                case _:
                    print('Unregistered/Unavailable service\n')

            try:
                client_socket.close()
            except:
                pass
