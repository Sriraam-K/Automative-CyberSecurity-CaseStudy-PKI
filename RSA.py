from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes
from X509 import certificate_from_pem, pem_from_cert
import datetime


# Function to generate private and public key pairs
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


# Function to verify a signed digital certificate with a public key
def verify_certificate(public_key_pem, certificate_pem):
    public_key = serialization.load_pem_public_key(public_key_pem)
    cert = certificate_from_pem(certificate_pem)
    try:
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA512()
        )
        print('Certificate issued by the trusted PKI.')
        # Check for certificate validity period
        current_time = datetime.datetime.now()
        if current_time > cert.not_valid_before and current_time < cert.not_valid_after:
            print('Certificate is currently active and valid')
            return True
        else:
            print('Certificate has expired or yet to activate')
            return False
    except Exception:
        print('Certificate verification failed. It may not be issued by the trusted PKI.')
        return False


# Function to sign a message digest with a private key
def sign_message_digest(private_key_pem, message_digest):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        message_digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA512())
    )
    return signature


# Function to verify a signed message digest with a public key
def verify_message_digest(public_key_pem, message_digest, signature):
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            message_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA512())
        )
        return True
    except:
        return False
