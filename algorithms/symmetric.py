import json
import timeit
import tracemalloc
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, ChaCha20 
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


#Se genera clave de 32 bits.
def generate_key():
    return get_random_bytes(32)

#Cifrado y rendimiento de Chacha20.
def chacha20(data):

    results = {
        'algorithm': 'Chacha20',
        'plaintext': data['plaintext'],
        'key': data['key'].hex(),
        'encryption': None,
        'timeEncryption': None,
        'resourcesEncryption': None,
        'decode': None,
        'timeDecode': None,
        'resourcesDecode': None
    }

    print('Ejecutando cifrado Chacha20...')
    print('Texto en claro: ' + str(data['plaintext']))
    print('Llave: ' + str(data['key'].hex()))
    
    startTime = timeit.default_timer()
    tracemalloc.start()
    
    plaintext = bytes(data['plaintext'],'utf-8')
    key = data['key']
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(plaintext)
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ciphertext).decode('utf-8')
    result = json.dumps({'nonce':nonce, 'ciphertext':ct})

    end_time= timeit.default_timer()

    results['encryption'] = ciphertext.hex()
    results['timeEncryption'] = str(end_time-startTime)
    results['resourcesEncryption'] = 'Current Memory: {} Peak Memory: {}'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])
    tracemalloc.stop()
    
    print('Ejecutando descifrado Chacha20...')

    startTime = timeit.default_timer()
    tracemalloc.start()

    try:
        b64 = json.loads(result)
        nonce = b64decode(b64['nonce'])
        ciphertext = b64decode(b64['ciphertext'])
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        #print("The message was " + str(plaintext))
    except (ValueError, KeyError):
        print("Incorrect decryption")

    end_time= timeit.default_timer()
    results['decode'] = plaintext
    results['timeDecode'] = str(end_time-startTime)
    results['resourcesDecode'] = 'Current Memory: {} | Peak Memory: {}'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])

    tracemalloc.stop()

    return results


#Crifrado y rendiminto de AES-CBC.
def aes_cbc(data):
    results = {
        'algorithm': 'AES-CBC',
        'plaintext': data['plaintext'],
        'key': data['key'].hex(),
        'encryption': None,
        'timeEncryption': None,
        'resourcesEncryption': None,
        'decode': None,
        'timeDecode': None,
        'resourcesDecode': None
    }

    print('Ejecutando cifrado AES-CBC...')
    print('Texto en claro: ' + str(data['plaintext']))
    print('Llave: ' + str(data['key'].hex()))

    startTime = timeit.default_timer()
    tracemalloc.start()

    plaintext = bytes(data['plaintext'],'utf-8')
    key = data['key']
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})

    end_time = timeit.default_timer()
    results['encryption'] = ct_bytes.hex()
    results['timeEncryption'] = str(end_time-startTime)
    results['resourcesEncryption'] = 'Current Memory: {} Peak Memory: {}'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])
    tracemalloc.stop()

    print('Ejecutando descifrado AES-CBC...')

    startTime = timeit.default_timer()
    tracemalloc.start()

    try:
        b64 = json.loads(result)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt)
    except (ValueError, KeyError):
        print("Incorrect decryption")
    
    end_time = timeit.default_timer()
    results['decode'] = pt
    results['timeDecode'] = str(end_time-startTime)
    results['resourcesDecode'] = 'Current Memory: {} | Peak Memory: {}'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])

    tracemalloc.stop()
    return results



#Crifrado y rendiminto de AES-EBC.
def aes_ebc(data):
    results = {
        'algorithm': 'AES-EBC',
        'plaintext': data['plaintext'],
        'key': data['key'].hex(),
        'encryption': None,
        'timeEncryption': None,
        'resourcesEncryption': None,
        'decode': None,
        'timeDecode': None,
        'resourcesDecode': None
    }

    print('Ejecutando cifrado AES-EBC...')
    print('Texto en claro: ' + str(data['plaintext']))
    print('Llave: ' + str(data['key'].hex()))

    startTime = timeit.default_timer()
    tracemalloc.start()
    
    plaintext = bytes(data['plaintext'],'utf-8')
    key = data['key']

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext,32))
    
    end_time = timeit.default_timer()

    results['encryption'] = ciphertext.hex()
    results['timeEncryption'] = str(end_time-startTime)
    results['resourcesEncryption'] = 'Current Memory: {} Peak Memory: {}'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])
    tracemalloc.stop()

    print('Ejecutando descifrado AES-EBC...')

    startTime = timeit.default_timer()
    tracemalloc.start()
    plaintext = cipher.decrypt(ciphertext)
    print(unpad(plaintext, 32))

    end_time = timeit.default_timer()
    results['decode'] = str(unpad(plaintext, 32))
    results['timeDecode'] = str(end_time-startTime)
    results['resourcesDecode'] = 'Current Memory: {} | Peak Memory: {}'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])

    tracemalloc.stop()
    return results