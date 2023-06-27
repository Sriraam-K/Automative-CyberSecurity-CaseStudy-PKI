import socket
import random
import hashlib
from IPv4_Ports import *
from cryptography.hazmat.primitives import serialization
from RSA import generate_key_pair, verify_message_digest
from X509 import create_csr, certificate_from_pem , display_DigiCert

class ECU:
    def __init__(self):
        self.PR_ecu = None
        self.PU_ecu = None
        self.Digital_certificate = None
        self.PU_pki = None

    def generate_key_files(self):
        self.PR_ecu, self.PU_ecu = generate_key_pair()
        
        # Save private key and public key to a file
        with open('ecu_private_key.pem', 'wb') as file:
            file.write(self.PR_ecu)
        with open('ecu_public_key.pem', 'wb') as file:
            file.write(self.PU_ecu)

        print("ECU's Private Key\n\n", self.PR_ecu.decode())
        print("ECU's Public Key\n\n", self.PU_ecu.decode())   


    def apply_for_certificate(self):

        csr_pem = create_csr(self.PR_ecu)

        # Establish connection with PKI
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as PKI_sock:
            PKI_sock.connect((PKI_HOST, PKI_PORT))
            # Send CSR to PKI
            PKI_sock.send(b'IC')
            PKI_sock.sendall(csr_pem)
            # Receive signed certificate and PKI's public key
            self.Digital_certificate = PKI_sock.recv(4096)
            self.PU_pki = PKI_sock.recv(4096)

        # Save signed certificate to a file
        with open('ecu_certificate.pem', 'wb') as file:
            file.write(self.Digital_certificate)
        # Save PKI's public key to a file
        with open('pki_public_key.pem', 'wb') as file:
            file.write(self.PU_pki)
        
        print("\nECU's Digital Cerificate\n\n", self.Digital_certificate.decode())
        print("PKI's Public Key (received)\n\n", self.PU_pki.decode())
        display_DigiCert(self.Digital_certificate)


    def load_resources(self):
        try:
            # Load ECU's private key
            with open('ecu_private_key.pem', 'rb') as file:
                self.PR_t = file.read()
            # Load ECU's public key
            with open('ecu_public_key.pem', 'rb') as file:
                self.PU_t = file.read()
            # Load ECU's digital certificate
            with open('ecu_certificate.pem', 'rb') as file:
                self.Digital_certificate = file.read()
            # Load PKI's public key
            with open('pki_public_key.pem', 'rb') as file:
                self.PU_pki = file.read()

            print('All Resources loaded and device ready to function...')
        except:
            print('No resources found: Keys generating....')
            self.generate_key_files() 
            print('Applying for Digital Certificate')
            self.apply_for_certificate()


    def verify_response(self, signed_response):

        # Load the stored challenge hash
        with open('challenge.txt', 'rb') as file:
            stored_digest = file.read()    

        # Verify the signed response using PKI's public key
        response_digest = verify_message_digest(self.PU_pki, stored_digest, signed_response)
        
        # Compare the received response digest with the stored digest
        if response_digest == True:
            print('Tester granted access to ECU\n')
            return b'Access granted!'
        else:
            print('ECU denies access to Tester\n')
            return b'Access denied!'
        
    def activate_ecu(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((ECU_HOST, ECU_PORT))
            sock.listen(2)

            # Load resources
            self.load_resources()

            print('Listening for Service Requests from Tester(s)\n')

            while True:
                # Accept connection from Tester
                client_socket, address = sock.accept()
                print(f'New connection from {address}\n')

                # Receive service request from Tester
                service_request = client_socket.recv(2).decode()

                if service_request == 'AR':
                    # Generate a random challenge string
                    challenge = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890', k=256))

                    # Hash the challenge string using SHA-512
                    message_digest = hashlib.sha512(challenge.encode('utf-8')).digest()

                    # Store the message digest for later verification
                    with open('challenge.txt', 'wb') as file:
                        file.write(message_digest)

                    # Send the challenge string to the Tester
                    client_socket.send(challenge.encode('utf-8'))

                elif service_request == 'VR':
                    # Receive signed response from Tester
                    signed_response = client_socket.recv(4096)
            
                    # Verify the response
                    access_perm = self.verify_response(signed_response)
                    client_socket.sendall(access_perm)

                    client_socket.close()

                # Close the connection
                client_socket.close()


if __name__ == '__main__':
    # Create ECU object
    ADAS = ECU()
    
    # Activate the ECU to start functioning
    ADAS.activate_ecu()
