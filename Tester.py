import socket
import hashlib
from IPv4_Ports import *
from X509 import create_csr, certificate_from_pem, pem_from_cert, display_DigiCert
from cryptography.hazmat.primitives import serialization
from RSA import generate_key_pair, sign_message_digest


class Tester :
    def __init__(self):
        self.PR_t = None
        self.PU_t = None
        self.Digital_certificate = None
        self.PU_pki = None


    def generate_key_files(self):
        self.PR_t, self.PU_t = generate_key_pair()

        # Save private key and public key to a file
        with open('tester_private_key.pem', 'wb') as file:
            file.write(self.PR_t)
        with open('tester_public_key.pem', 'wb') as file:
            file.write(self.PU_t)

        print("Tester's Private Key\n\n", self.PR_t.decode())
        print("Tester's Public Key\n\n", self.PU_t.decode())       


    def apply_for_certificate(self):

        csr_pem = create_csr(self.PR_t)

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
        with open('tester_certificate.pem', 'wb') as file:
            file.write(self.Digital_certificate)
        # Save PKI's public key to a file
        with open('pki_public_key.pem', 'wb') as file:
            file.write(self.PU_pki)
        
        print("\nTester's Digital Cerificate\n\n", self.Digital_certificate.decode())
        print("PKI's Public Key (received)\n\n", self.PU_pki.decode())
        display_DigiCert(self.Digital_certificate)


    def load_resources(self):
        try:
            # Load Tester's private key
            with open('tester_private_key.pem', 'rb') as file:
                self.PR_t = file.read()
            # Load Tester's public key
            with open('tester_public_key.pem', 'rb') as file:
                self.PU_t = file.read()
            # Load Tester's digital certificate
            with open('tester_certificate.pem', 'rb') as file:
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


    def request_access(self):
        # Establish connection with ECU
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((Tester_HOST, Tester_PORT))
            sock.connect((ECU_HOST, ECU_PORT))
            # Send access request
            sock.sendall(b'AR')
            print('Sending ECU Access Request\n')
            # Receive challenge string from ECU
            challenge = sock.recv(256).decode('utf-8')
            print('Challenge received from ECU\n')
            print(challenge, '\n')

        sock.close() 

        return challenge


    def authenticate(self, challenge, pki_public_key):
        # Hash the challenge string using SHA-512
        message_digest = hashlib.sha512(challenge.encode()).digest()
        # Sign the message digest with tester's private key
        signature = sign_message_digest(self.PR_t, message_digest)

        # Establish connection with PKI
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((Tester_HOST, Tester_PORT))
            sock.connect((PKI_HOST, PKI_PORT))
            sock.send(b'VT')

            # 1st step authentication
            username = input(f'{sock.recv(15).decode()}')
            sock.send(username.encode())
            password = input(f'{sock.recv(15).decode()}')
            sock.send(password.encode())
            login_status = sock.recv(36).decode()
            print(login_status)

            # 2nd step authentication
            try:
                if login_status == '1st step Authentication Failed......':
                    sock.close()
                    raise Exception('Connection Aborted')
            except Exception as e:
                print(e)
                return b'fail'
                
            msg = sock.recv(40).decode()
            print(msg)
            if msg == 'Send Details for 2nd step Authentication':    
                # Send signed message digest and tester's certificate for authentication
                print('Sending details for Authentication\n')
                sock.sendall(challenge.encode())
                sock.sendall(signature)
                sock.sendall(self.Digital_certificate)

                # Receive signed response from PKI
                signed_response = sock.recv(4096)
                print('Received Challenge Signature\n')

        return signed_response


if __name__ == '__main__':
    T1 = Tester()
    # Load Resources
    T1.load_resources()

    # Request access
    challenge = T1.request_access()
    
    # Authenticate
    signed_response = T1.authenticate(challenge, T1.PU_pki)
    
    if signed_response != b'fail':
        # Send the signed response back to ECU
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((Tester_HOST, Tester_PORT))
            sock.connect((ECU_HOST, ECU_PORT))
            sock.send(b'VR')
            sock.sendall(signed_response)
            print('Waiting for Access from ECU ...\n')
            access = sock.recv(64)
            print(access.decode())
