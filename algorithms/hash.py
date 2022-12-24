import timeit
import tracemalloc
from Crypto.Hash import SHA384, SHA3_384, SHA512, SHA3_512

#Cifrado con SHA-2 (384 bits).
def sha2_384(data):
    results = {
        'algorithm': 'HASH-2 (384 bits)',
        'plaintext': data,
        'encryption': None,
        'timeEncryption': None,
        'resourcesEncryption': None,
    }

    print('Ejecutando cifrado HASH-2 (384 bits)...')
    print('Texto en claro: ' + data)

    startTime = timeit.default_timer()
    tracemalloc.start()
    
    h = SHA384.new()
    h.update(bytes(data,'utf-8'))

    end_time= timeit.default_timer()

    results['encryption'] = h.hexdigest()
    results['timeEncryption'] = str(end_time-startTime)
    results['resourcesEncryption'] = 'Current Memory: {} Peak Memory: {}'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])
    tracemalloc.stop()

    return results

#Cifrado con SHA-3 (384 bits).
def sha3_384(data):
    results = {
        'algorithm': 'HASH-3 (384 bits)',
        'plaintext': data,
        'encryption': None,
        'timeEncryption': None,
        'resourcesEncryption': None,
    }

    print('Ejecutando cifrado HASH-2 (384 bits)...')
    print('Texto en claro: ' + data)

    startTime = timeit.default_timer()
    tracemalloc.start()
    
    h = SHA3_384.new()
    h.update(bytes(data,'utf-8'))

    end_time= timeit.default_timer()

    results['encryption'] = h.hexdigest()
    results['timeEncryption'] = str(end_time-startTime)
    results['resourcesEncryption'] = 'Current Memory: {} Peak Memory: {}'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])
    tracemalloc.stop()

    return results

#Cifrado con SHA-2 (512 bits).
def sha2_512(data):
    results = {
        'algorithm': 'HASH-2 (512 bits)',
        'plaintext': data,
        'encryption': None,
        'timeEncryption': None,
        'resourcesEncryption': None,
    }

    print('Ejecutando cifrado HASH-2 (384 bits)...')
    print('Texto en claro: ' + data)

    startTime = timeit.default_timer()
    tracemalloc.start()
    
    h = SHA512.new()
    h.update(bytes(data,'utf-8'))

    end_time= timeit.default_timer()

    results['encryption'] = h.hexdigest()
    results['timeEncryption'] = str(end_time-startTime)
    results['resourcesEncryption'] = 'Current Memory: {} Peak Memory: {}'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])
    tracemalloc.stop()

    return results


#Cifrado con SHA-3 (512 bits).
def sha3_512(data):
    results = {
        'algorithm': 'HASH-3 (512 bits)',
        'plaintext': data,
        'encryption': None,
        'timeEncryption': None,
        'resourcesEncryption': None,
    }

    print('Ejecutando cifrado HASH-2 (384 bits)...')
    print('Texto en claro: ' + data)

    startTime = timeit.default_timer()
    tracemalloc.start()
    
    h = SHA3_512.new()
    h.update(bytes(data,'utf-8'))

    end_time= timeit.default_timer()

    results['encryption'] = h.hexdigest()
    results['timeEncryption'] = str(end_time-startTime)
    results['resourcesEncryption'] = 'Current Memory: {} Peak Memory: {}'.format(tracemalloc.get_traced_memory()[0], tracemalloc.get_traced_memory()[1])
    tracemalloc.stop()

    return results