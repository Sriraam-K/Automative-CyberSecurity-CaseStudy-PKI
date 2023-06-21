from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import CertificateBuilder, Name, NameAttribute
from cryptography.x509.oid import NameOID
import datetime
import random

# Function to generate digital certificate serial number
def generate_serial_number():
    digits = list(range(1, 10))  
    random.shuffle(digits)  
    number = ''
    for _ in range(6):
        digit = digits.pop() 
        number += str(digit)

    return int(number)

# Function to create a digital certificate signing request (CSR)
def create_csr(private_key):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, input("Country Name (2 letter code): ")),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, input("State or Province Name: ")),
        x509.NameAttribute(NameOID.LOCALITY_NAME, input("Locality Name (e.g., city): ")),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, input("Organization Name (e.g., company): ")),
        x509.NameAttribute(NameOID.COMMON_NAME, input("Common Name (e.g., your name or server's hostname): ")),
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).sign(
        private_key, hashes.SHA512(), default_backend()
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    return csr_pem

# Function to build a digital certificate from a CSR
def build_certificate(csr_pem, pki_private_key):
    # Load the CSR
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())

    # Create the certificate builder
    builder = CertificateBuilder()

    # Set the subject name from the CSR
    builder = builder.subject_name(csr.subject)

    # Set the issuer name (e.g., PKI's name)
    issuer_name = Name([
        NameAttribute(NameOID.COUNTRY_NAME, 'IN'),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Karnataka'),
        NameAttribute(NameOID.LOCALITY_NAME, 'Bengaluru'),
        NameAttribute(NameOID.ORGANIZATION_NAME, 'PKI CyberTrust Organization'),
        NameAttribute(NameOID.COMMON_NAME, 'PKI CyberTrust')
    ])
    builder = builder.issuer_name(issuer_name)

    # Set the public key from the CSR
    builder = builder.public_key(csr.public_key())

    # Set the serial number (e.g., unique identifier for the certificate)
    builder = builder.serial_number(generate_serial_number())

    # Set the validity period for the certificate (e.g., 1 year)
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))

    # Set the Basic constraints ie., indicate not part of CA
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )   

    # Create a set of all key usages
    key_usage_extension = x509.KeyUsage(
        digital_signature=True,
        content_commitment=True,
        key_encipherment=True,
        data_encipherment=True,
        key_agreement=True,
        key_cert_sign=False,
        crl_sign=True,
        encipher_only=True,
        decipher_only=True
    )

    # Define Public key usage added to the digital certificat
    builder = builder.add_extension(
        key_usage_extension,
        critical=True
    )

    # Sign the certificate with PKI's private key
    certificate = builder.sign(pki_private_key, hashes.SHA512(), padding.PKCS1v15())

    # Return the certificate in PEM format
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    
    return certificate_pem

def certificate_from_pem(cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    return cert

def pem_from_cert(cert):
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    return cert_pem

def display_DigiCert(cert_pem):
    # Decode the PEM-encoded certificate
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

    version = cert.version.name
    serial_number = cert.serial_number

    # Subject Details
    subject = cert.subject
    subject_details = {}
    for attribute in subject:
        attr_name = attribute.oid._name
        attr_value = attribute.value
        subject_details[attr_name] = attr_value

    # Issuer Details
    issuer = cert.issuer
    issuer_details = {}
    for attribute in issuer:
        attr_name = attribute.oid._name
        attr_value = attribute.value
        issuer_details[attr_name] = attr_value

    # Displaying the Certificate Details
    print('\n-----BEGIN CERTIFICATE-----\n')
    print("Certificate Version:", version)
    print("\nSerial Number:", serial_number)
    print("\nSubject Details:\n")
    for attr_name, attr_value in subject_details.items():
        attr_name = attr_name[0].upper() + attr_name[1:]
        print(attr_name + ":", attr_value)
    print("\nIssuer Details:\n")
    for attr_name, attr_value in issuer_details.items():
        attr_name = attr_name[0].upper() + attr_name[1:]
        print(attr_name + ":", attr_value)
    print('\nValidity Time Interval Details:')
    print('Not Valid Before:',cert.not_valid_before)
    print('Not Valid After:',cert.not_valid_after)
    
    # Extension Details
    extensions = cert.extensions
    print("\nCertificate Extensions:\n")
    for extension in extensions:
        print("Name:", extension.oid._name, '\n')

        if extension.oid.dotted_string == "2.5.29.19":  # Basic Constraints extension
            basic_constraints = extension.value
            print("CA:", basic_constraints.ca)
            print("Path Length:", basic_constraints.path_length)

        if extension.oid.dotted_string == "2.5.29.15":  # Key Usage extension
            key_usage = extension.value
            for attr in dir(key_usage):
                if not attr.startswith("_"):
                    attr_name = attr[0].upper() + attr[1:]
                    print(attr_name, ":", getattr(key_usage, attr))

        print()

    print('\nSignature Algorithm:', cert.signature_algorithm_oid._name)
    print("\nHashing Algorithm:", cert.signature_hash_algorithm.name)
    print("\nDigital Signature:", cert.signature)
    print('\n-----END CERTIFICATE-----\n')