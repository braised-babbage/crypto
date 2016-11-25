"""Simple implementation of RSA cryptosystem. 

Use keygen to make a key pair, and then encode/decode to handle an (integer) message.

"""

from random import randint


def modexp(x,y,N):
    """ Computes x^y mod N.
    
    >>> modexp(2,3,10)
    8
    >>> modexp(2,3,5)
    3
    
    """
    if y == 0:
        return 1
    z = modexp(x,y//2,N)
    if y % 2 == 0:
        return z**2 % N
    return x*(z**2) % N


def extended_euclid(a,b):
    """ Returns m,n,d such that d = gcd(a,b) and ma + nb = d.

    >>> extended_euclid(5,0)
    (1, 0, 5)

    >>> extended_euclid(15,7)
    (1, -2, 1)
    """
    if b == 0:
        return 1,0,a
    m,n,d = extended_euclid(b, a % b)
    # xb + y(a-(a//b)b) = d
    return n,m-(a//b)*n,d


def modinv(a,N):
    """ Returns x such that ax = 1 mod N. 
    
    >>> modinv(2,7)
    4
    """
    m,_,d = extended_euclid(a,N)
    if d != 1:
        raise Exception("Zero divisor")
    return m % N



def fermat_test(N, alphas=10):
    """ True if N passes the Fermat test for primality. 

    >>> fermat_test(61)
    True

    >>> fermat_test(62)
    False
    """
    if type(alphas) == int:
        alphas = [randint(1,N-1) for i in range(alphas)]
    for a in alphas:
        z = modexp(a,N-1,N)
        if z != 1:
            return False
    return True


def randprime(lower,upper):
    """ Returns a random prime in the interval [lower,upper]. """
    alphas = [2,3,5,7,11,13,17,19]
    while True:
        n = randint(lower,upper)
        if fermat_test(n,alphas):
            return n


def keygen(nbits):
    """ Computes a public,private key pair from two
random primes of size nbits."""
    
    lower,upper = 2**(nbits-1),2**nbits-1
    p = randprime(lower,upper)
    q = randprime(lower,upper)
    N = p*q

    e = 3
    while True:
        try:
            d = modinv(e,(p-1)*(q-1))
            break
        except:
            e += 1

    return ((N,e),(N,d))


def encode(public_key, msg):
    """ Encode msg using public_key.

    >>> encode((12087136410462725761, 5), 1337)
    4272253717090457
    """
    N,e = public_key
    return modexp(msg,e,N)


def decode(private_key, msg):
    """ Decode msg using private_key.
    
    >>> decode((12087136410462725761, 4834854561401929901), 4272253717090457)
    1337
    """ 
    N,d = private_key
    return modexp(msg,d,N)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
