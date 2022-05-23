from pwn import *
from functools import reduce
from sage.all import *
from Crypto.Util.number import bytes_to_long,long_to_bytes
from Crypto.PublicKey import RSA
import requests,re
from gmpy2 import iroot

# input a and b
# output (x,y) (solve of ax + by = gcd(a,b))
def extern_gcd(a,b):
    q = a // b
    r = a % b
    if (b % r) == 0:
        return 1,-q
    x,y = extern_gcd(b,r)
    return y,(x - q*y)


# input a oracle func and r(pwn remote object)
# output the plain(bytes) of prepend oracle server
# oracle func : input a message(bytes) and r(pwn remote object) than output (message + plain)'s cipher(bytes)
def prepend_oracle_attack(oracle,r):
    plainlength = len(oracle(b'',r))
    plain = b''
    print('')
    print('',b'attacking : ',end='')
    for j in range(plainlength):
        correct = oracle(b'a'*(plainlength-1-j),r)[:plainlength]
        for i in range(256):
            test = b'a'*(plainlength-1-j)+plain+bytes([i])
            plaintest = oracle(test,r)[:plainlength]
            if plaintest == correct:
                plain = plain + bytes([i])
                break
        print('\r',b'attacking : ' + plain,end='')
    print('\n')
    return plain


# input orginal (iv + cipher)(bytes) and oracle func and r (pwn remote object)
# output the plain(bytes) of padding oracle server
# oracle func : input a (iv + cipher)(bytes) and r(pwn remote object) than output a boolean
#               the boolean mean (iv + cipher)'s plain's padding is/not correct
def padding_oracle_attack(cipher, oracle ,r):
    blocknum = int(len(cipher)//16)
    plain = b''
    print('')
    print('',b'attacking : ',end='')
    for ii in range(blocknum - 1):
        ciphercopy = b''
        if ii == 0:
            ciphercopy = cipher
        else:
            ciphercopy = cipher[:16*(blocknum - ii-1)] + cipher[16*(blocknum-1):] + cipher[16*(
                blocknum-ii):16*(blocknum-1)] + cipher[16*(blocknum-ii-1):16*(blocknum-ii)]
        iv = ciphercopy[16*(blocknum-2):16*(blocknum-1)]
        plain2 = b''
        for j in range(16):
            ivtest = b''
            last = xor(iv, plain2, bytes([0]*(16-j)+[j+1]*j))
            for i in range(256):
                ivtest = iv[:15-j] + bytes([i]) + bytes(last[16-j:])
                ciphertest = ciphercopy[:16*(blocknum-2)] + \
                    ivtest + ciphercopy[16*(blocknum-1):]
                bol = oracle(ciphertest,r)
                if j == 0:
                    if (bol and (iv != ivtest)):
                        break
                else:
                    if bol:
                        break
            plain2 = xor(bytes([0]*(15-j) + [j+1]*(j+1)), ivtest, iv)
        if ii != 0:
            plain2 = xor(plain2, ciphercopy[16*(blocknum-2):16*(blocknum-1)],
                         ciphercopy[16*(blocknum-2-ii):16*(blocknum-1-ii)])
        plain = plain2 + plain
        print('\r',b'attacking : ' + plain,end='')
    print('\n')
    return plain


# input s0(seed)(int) , m(int) , inc(int) , N(int)(modolus)
# output next lcg random
def next_lcg_random(s0,m,inc,N):
    return (m*s0 + inc) % N


# input s0(seed)(int) , m(int) , inc(int) , N(int)(the modolus) , n(int)
# output the nth random number of lcg (doesn't count seed)
def lcg_random(s0,m,inc,N,n):
    num = s0
    for _ in range(n):
        num = next_lcg_random(num,m,inc,N)
    return num


# input state of lcg (list)
# output [seed(statep[0]) , m , inc , N]
def lcg_attack(state):
    t = []
    for i in range(len(state)-1):
        t.append(state[i+1] - state[i])
    tt = []
    for i in range(len(t)-2):
        tt.append(t[i+2]*t[i]-t[i+1]*t[i+1])
    N = reduce(gcd,tt)
    m = extern_gcd(t[0],N)[0] * t[1] % N
    inc = (state[1] - state[0]*m) % N
    return [state[0],m,inc,N]

# input a enc file name(str)
# output the int transfer from enc's data
def enc2long(enc_file):
    with open(enc_file,mode='rb') as f:
        cipher = bytes_to_long(f.read().strip())
    return cipher


# input a pem file name(str)
# output (n,e) (int) of the pem file
def pem2key(pem_file):
    key = RSA.importKey(open(pem_file).read())
    return int(key.n),int(key.e)


# input a number(int)
# output the factor list of the number (list) (factor is from factordb.com)
def factor_online(n):
    base_url = 'http://factordb.com/'
    url = base_url + 'index.php?query=' + str(n)
    r = requests.get(url)
    search_str = str(re.search(r'<tr><td>.*</td>\n<td>.*</td>\n<td>(.*)</td>\n</tr>',str(r.text)).group(1))
    factor_ori_list = re.findall(r'<font color="#\d*">(.*?)</font>',search_str)[1:]
    factor_fin_list = []
    for i in range(len(factor_ori_list)):
        if '.' in factor_ori_list[i]:
            next_url = base_url + 'index.php?id=' +\
                str(re.search(r'<a href="index.php\?id=(\d*)"><font color="#\d*">' + factor_ori_list[i] + r'</font>',search_str).group(1))
            next_r = requests.get(next_url)
            value = int(str(re.search(r'<center>\n(.*)\n.*\n</center>',str(next_r.text)).group(1)).split('value="')[1][:-2])
            factor_fin_list.append(value)
        elif '^' in factor_ori_list[i]:
            [value,num] = factor_ori_list[i].split('^')
            for _ in range(int(num)):
                factor_fin_list.append(int(value))
        else:
            factor_fin_list.append(int(factor_ori_list[i]))
    return factor_fin_list


# input p , q , e , n , cipher (int)
# output m (decrypt from cipher)(int)
def rsa_decrypt_from_pq(p,q,e,n,cipher):
    phi = (p - 1)*(q - 1)
    d = int(pow(e,-1,phi))
    m = int(pow(cipher,d,n))
    return m


# input beta(any numeric type) , epsilon(any numeric type) , N(int) , f (polynomial of x)
# output small root(int) of f(x) ≡ 0 (mod b) if there's no than return 0 
def coppersmith_method(beta,epsilon,N,f):
    N = Integer(N)
    delta = Integer(f.degree())
    X = ceil(N**(beta**2 / (delta) - epsilon))
    smallroot = f.small_roots(X,beta,epsilon)
    try:
        smallroot = smallroot[0]
    except:
        return 0
    return int(smallroot)


# input mbar(the know message)(int) , c(int) , e(int) , N(int) , epsilon(numeric)
# output the unknow message x0 (m = mbar + x0)(int)
def stereotyped_message(mbar,c,e,N):
    mbar = Integer(mbar)
    c = Integer(c)
    e = Integer(e)
    N = Integer(N)
    Z = PolynomialRing(Zmod(N),implementation='NTL', names=('x',)); (x,) = Z._first_ngens(1)
    f = (mbar + x)**e - c
    smallroot = coppersmith_method(1,1/Integer(13),N,f)
    return smallroot


# input k (sage.rings.rational.Rational)
# output k's continued fraction list (in sage.rings.rational.Rational)
def seq_of_countinued_fraction(k):
    a = k.continued_fraction_list()
    seq = []
    for i in range(len(a)):
        b = Integer(0)
        for j in range(i,-1,-1):
            if b == 0:
                b = a[j]
            else:
                b = Integer(1) / b + a[j]
        seq.append(b)
    return seq


# input n,e,c (int)
# output m(int) (plain of c)
def wiener_attack(n,e,c):
    y = var('y')
    seq = seq_of_countinued_fraction(Integer(e)/Integer(n))
    p = 0
    dt = 0
    for i in range(2,len(seq)):
        print(seq[i])
        k = seq[i].numerator()
        d = seq[i].denominator()
        b = (e*d - Integer(1))/k - n - 1
        pp = (y**2 + b*y + n).roots()[1][0]
        if not pp in NN:
            continue
        if (n % int(pp)) == 0:
            dt = int(d)
            break
    return int(pow(c,dt,n))

# input n1 , n2 (sage.rings.rational.Rational)
# if there's a integer between [n1,n2) than return that number(int) , else -1
def is_between(n1,n2):
    if (n1 in NN) and (n2 in NN):
        if (n2 - n1) == 1:
            return int(n1)
        return -1
    if (n1 in NN):
        if (n2 - n1) <= 1:
            return int(n1)
        return -1
    if (n2 in NN):
        if 2 > (n2 - n1) >= 1:
            return int(ceil(n1))
        return -1
    if (ceil(n1) == floor(n2)):
        return int(ceil(n1))
    return -1

# it's with LSB oracle attack (just write for more beauty)
def binary_search(seq,n,e,oracle,r):
    [n1,n2,c] = seq
    if is_between(n1,n2) != -1:
        return [is_between(n1,n2)]*2 + [c]
    cc = int(pow(2,e,n))*c % n
    bo = oracle(cc,r)
    if bo == 0:
        n2 = (n1 + n2)/2
    else :
        n1 = (n1 + n2)/2
    return [n1,n2,cc]


# input n , e , c(int) , oracle func , r(pwn remote object)
# output m(int)
# oracle func : intput c(int) and r(pwn remote object) than output lowwest bit of cipher's plain(int)
def LSB_oracle_attack(n,e,c,oracle,r):
    seq = [Integer(0),Integer(n),c]
    while True:
        seq = binary_search(seq,n,e,oracle,r)
        if seq[0] == seq[1]:
            return seq[0]


# input n(int) and pbar(int)
# output (p,q) (int) (factors of n)
def known_high_bits_of_p(n,pbar):
    n = Integer(n)
    pbar = Integer(pbar)
    Z = PolynomialRing(Zmod(n),implementation='NTL', names=('x',)); (x,) = Z._first_ngens(1)
    f = pbar + x
    smallroot = coppersmith_method(0.5,0.5/8,n,f)
    p = pbar+smallroot
    assert (n % p) == 0
    q = n // p
    return p,q


# input f1 , f2(polynomial)
# output the gcd of f1 and f2(polynomial)
def polynomialgcd(f1,f2):
    Z = PolynomialRing(ZZ, names=('x',)); (x,) = Z._first_ngens(1)
    if f2 == 0:
        f1 = f1 / f1.coefficients()[-1]
        return f1
    if f2.degree()>f1.degree():
        ex = f2
        f2 = f1
        f1 = ex
    diff = int(f1.degree()- f2.degree())
    coe = (f1.coefficients()[-1])/(f2.coefficients()[-1])
    g = f1 - f2*coe*(x**(diff))
    return polynomialgcd(f2,g)


# input n (int), e (int), c1 (int), c2 (int), f (polynomial Zmod(n)) (f(m1) = m2)
# output m1 (int)
def franklin_reiter(n,e,c1,c2,f):
    n = Integer(n)
    e = Integer(e)
    c1 = Integer(c1)
    c2 = Integer(c2)
    Z = PolynomialRing(Zmod(n),implementation='NTL', names=('x',)); (x,) = Z._first_ngens(1)
    g1 = x**e - c1
    g2 = f**e - c2
    m1 = int(-polynomialgcd(g1,g2)[0])
    return m1


# input e(int)  , d(int)  , n(int)
# output a n's factor(int)
def factor_n_with_d(e,d,n):
    k = e*d - 1
    for g in range(2,n):
        if gcd(g,n) != 1:
            return int(gcd(g,n))
        kk = k
        while (kk % 2) == 0:
            kk = kk//2
            gg = int(pow(g,kk,n))
            if 1 < gcd(n,gg+1)<n:
                return int(gcd(gg+1,n))
            if 1<gcd(n,gg-1)<n:
                return int(gcd(gg-1,n))


# input n(int) , c1(int) , c2(int) , e(int) (m1 = (2^k)m + r1)(m2 = (2^k)m + r2)
# output m1(int)
def coppersmith_short_pad_attack(n,c1,c2,e):
    n = Integer(n)
    c1 = Integer(c1)
    c2 = Integer(c2)
    e = Integer(e)
    ZmodN = Zmod(n)
    Z = PolynomialRing(ZZ, names=('x', 'y',)); (x, y,) = Z._first_ngens(2)
    g1 = x**e - c1
    g2 = (x + y)**e - c2
    h = g1.resultant(g2,x)
    h = h.univariate_polynomial()
    h = h.change_ring(ZmodN)
    diff = h.small_roots(epsilon=1/Integer(30))[0]
    Z = PolynomialRing(ZmodN, names=('x',)); (x,) = Z._first_ngens(1)
    f = x + diff
    m1 = franklin_reiter(n,e,c1,c2,f)
    return m1


# input n(int) (p and q need to be near)
# output (p,q) (n's factor)(int)
def fermat_factor(n):
    a = int(sqrt(n)) + 1
    b = 0
    while True:
        bb = int(a**2 - n)
        if iroot(bb,int(2))[1]:
            b = int(iroot(bb,int(2))[0])
            break
        a = a + 1
    assert n%(a+b) == 0
    assert n%(a-b) == 0
    return int(a+b),int(a-b)


# input n(int)
# output one of the n's prime factor(int)
def simple_factor(n):
    if is_prime(n):
        return n
    for i in range(2,n):
        if (n%i) == 0:
            return simple_factor(i)


# input n(int)((p-1)'s biggest prime factor is realy small)
# output one of the n's prime factor(int)
def pollard_algorithm(n):
    if is_prime(n):
        return n
    a = 2
    b = 2
    while True:
        a = int(pow(a,b,n))
        d = int(gcd(a - 1,n))
        if 1 < d < n:
            if is_prime(d):
                return d
            return simple_factor(d)
        b = b + 1


