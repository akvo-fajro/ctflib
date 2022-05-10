from ctflib.crypto import *
'''
already import :

from pwn import *
from functools import reduce
from sage.all import *
from Crypto.Util.number import bytes_to_long,long_to_bytes
from Crypto.PublicKey import RSA
import requests,re
from gmpy2 import iroot
'''
#######################################
###### place the code down below ######
#######################################

# sage : Z.<x> = PolynoamialRing(Zmod(n),implementation='NTL')
# Z = PolynomialRing(Zmod(n),implementation='NTL', names=('x',)); (x,) = Z._first_ngens(1) 

# sage : Z.<x> = PolynomialRing(ZZ)
# Z = PolynomialRing(ZZ, names=('x',)); (x,) = Z._first_ngens(1)

