import json
import timeit
import tracemalloc
import Crypto
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from ecdsa import SigningKey



def rsa_oaep(data):
    results = {
        'algorithm': 'RSA-OAEP',
        'plaintext': data,
        'publicKey': None,
        'privateKey': None,
        'signarute': None,
        'timeSignature': None,
        'resourcesSignature': None,
        'verify': None,
        'timeVerify': None,
        'resourcesVerify': None
    }

    print('Proceso de Firma...')

    #Tiempo y recursos de la firma.
    startTime = timeit.default_timer()
    tracemalloc.start()

    #Se obtienen las claves pública y privada.
    rsa_private_key = RSA.generate(1024, Crypto.Random.new().read)
    rsa_public_key = rsa_private_key.public_key()
    
    #Se codifica el mensaje en claro a bytes.
    plaintext = bytes(data,'utf-8')

    #Se realiza el profeso de firma.
    key = RSA.importKey(rsa_public_key.export_key())
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext)

    end_time= timeit.default_timer()

    results['privateKey'] = rsa_private_key.export_key()
    results['publicKey'] = rsa_public_key.export_key()
    results['signarute'] = ciphertext.hex()
    results['timeSignature'] = str(end_time-startTime)
    results['resourcesSignature'] = 'Current Memory: {} bytes Peak Memory: {} bytes'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])
    tracemalloc.stop()

    print('Proceso de verificación...')

    #Tiempo y recursos de verificación.
    startTime = timeit.default_timer()
    tracemalloc.start()

    key = RSA.importKey(rsa_private_key.export_key())
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)

    end_time= timeit.default_timer()

    results['verify'] = plaintext
    results['timeVerify'] = str(end_time-startTime)
    results['resourcesVerify'] = 'Current Memory: {} bytes Peak Memory: {} bytes'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])
    tracemalloc.stop()

    return results



def rsa_pss(data):
    results = {
        'algorithm': 'RSA-PSS',
        'plaintext': data,
        'publicKey': None,
        'privateKey': None,
        'signarute': None,
        'timeSignature': None,
        'resourcesSignature': None,
        'verify': None,
        'timeVerify': None,
        'resourcesVerify': None
    }

    print('Proceso de Firma...')

    #Tiempo y recursos de la firma.
    startTime = timeit.default_timer()
    tracemalloc.start()

    #Se obtienen las claves pública y privada.
    rsa_private_key = RSA.generate(1024, Crypto.Random.new().read)
    rsa_public_key = rsa_private_key.public_key()
    
    #Se codifica el mensaje en claro a bytes.
    plaintext = bytes(data,'utf-8')

    #Se realiza el profeso de firma.
    key = RSA.import_key(rsa_private_key.export_key())
    h = SHA256.new(plaintext)
    signature = pss.new(key).sign(h)

    end_time= timeit.default_timer()

    results['privateKey'] = rsa_private_key.export_key()
    results['publicKey'] = rsa_public_key.export_key()
    results['signarute'] = signature.hex()
    results['timeSignature'] = str(end_time-startTime)
    results['resourcesSignature'] = 'Current Memory: {} bytes Peak Memory: {} bytes'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])
    tracemalloc.stop()

    print('Proceso de verificación...')

    #Tiempo y recursos de verificación.
    startTime = timeit.default_timer()
    tracemalloc.start()

    key = RSA.import_key(rsa_public_key.export_key())
    h = SHA256.new(plaintext)
    verifier = pss.new(key)
    try:
        verifier.verify(h, signature)
        print ("La firma es auténtica.")
    except (ValueError, TypeError):
        print ("La firma no es auténtica.")

    end_time= timeit.default_timer()

    results['verify'] = plaintext
    results['timeVerify'] = str(end_time-startTime)
    results['resourcesVerify'] = 'Current Memory: {} bytes Peak Memory: {} bytes'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])
    tracemalloc.stop()

    return results


from ecdsa import SigningKey




def ecdsa(data):
    results = {
        'algorithm': 'ECDSA',
        'plaintext': data,
        'publicKey': None,
        'privateKey': None,
        'signarute': None,
        'timeSignature': None,
        'resourcesSignature': None,
        'verify': None,
        'timeVerify': None,
        'resourcesVerify': None
    }

    sk = SigningKey.generate()
    vk = sk.verifying_key

    print('Proceso de Firma...')

    #Tiempo y recursos de la firma.
    startTime = timeit.default_timer()
    tracemalloc.start()

    #Se obtienen las claves pública y privada.    
    with open("private.pem", "wb") as f:
        f.write(sk.to_pem())
    with open("public.pem", "wb") as f:
        f.write(vk.to_pem())

    #Se codifica el mensaje en claro a bytes.
    plaintext = bytes(data,'utf-8')

    #Se realiza el profeso de firma.
    key = ECC.import_key(open('private.pem').read())
    h = SHA256.new(plaintext)
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(h)

    end_time= timeit.default_timer()

    results['privateKey'] = key
    results['signarute'] = signature.hex()
    results['timeSignature'] = str(end_time-startTime)
    results['resourcesSignature'] = 'Current Memory: {} bytes Peak Memory: {} bytes'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])
    tracemalloc.stop()

    print('Proceso de verificación...')

    #Tiempo y recursos de verificación.
    startTime = timeit.default_timer()
    tracemalloc.start()
    
    key = ECC.import_key(open('public.pem').read())
    h = SHA256.new(plaintext)
    verifier = DSS.new(key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        print ("The message is authentic.")
    except ValueError:
        print ("The message is not authentic.")

    end_time= timeit.default_timer()

    results['publicKey'] = key
    results['verify'] = plaintext
    results['timeVerify'] = str(end_time-startTime)
    results['resourcesVerify'] = 'Current Memory: {} bytes Peak Memory: {} bytes'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])
    tracemalloc.stop()

    return results