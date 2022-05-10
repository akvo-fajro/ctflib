# Crypto Function Usage

## block cipher mode of AES

### prepend oracle attack
**condition** : server can recv msg and send back the (msg + plain)'s cipher (encrypt/decrypt by AES's ECB mode)<br>
**function** : `plain(bytes) = prepend_oracle_attack(oracle)`<br>
**parameter** : 
- `oracle` (func) : input msg(bytes) and send it to server than return (msg + plain)'s cipher(bytes) recv from server<br>

**output** : 
- `plain` (bytes) :  the plaintext of prepend oracle server<br>
<br>

### padding oracle attack
**condition** : server can recv (iv + cipher) and send back if the padding of plaintext (decrypt from cihper) right/wrong and server give a cipher of server's (iv + plaintext) (encrypt/decrypt by AES's CBC mode)<br>
**function** : `plain(bytes) = padding_oracle_attack(cipher,oracle)`<br>
**parameter** : 
- `cipher` (bytes) : the (iv + orginal_plaintext)'s cipher<br>
- `oracle` (func) : input (iv + cipher)(bytes) and send it to server than return is (iv + cipher)'s plaintext's padding right/wrong (bool)<br>

**output** : 
- `plain` (bytes) : the plaintext of padding oracle server<br>
<br>


## LCG

### lcg random
**condition** : none<br>
**function** : `rand_num(int) = lcg_random(s0,m,inc,N,n)`<br>
**parameter** :
- `s0` , `m` , `inc` , `N` (int): s0 is seed of lcg and every is lcg's param
- `n` (int): represent the nth random number of lcg you want to get (doesn't count the seed)<br>

**output** : 
- `rand_num` (int) : the nth random num of lcg<br>
<br>

### lcg attack
**condition** : there's enough state of same lcg (well... same param)<br>
**function** : `[s0,m,inc,N] = lcg_attack(state)`<br>
**parameter** :
- `state` (list of int): the state of lcg<br>

**output** :
- `s0` , `m` , `inc` , `N` (int) : the param of lcg<br>
<br>


## RSA

### encfile to int
**condition** : none<br>
**function** : `cipher(int) = enc2long(enc_file)`<br>
**parameter** :
- `enc_file` (str) : enc file's name<br>

**output** :
- `cipher` (int) : the data in the enc transform to int<br>
<br>

### pemfile to rsa key
**condition** : none<br>
**funciton** : `(n,e) = pem2key(pem_file)`<br>
**parameter** :
- `pem_file` (str) : pem file's name<br>

**output** :
- `n` , `e` (int): the number of rsa public key<br>
<br>

### factor online
**condition** : need internet<br>
**function** : `factor_seq(list) = factor_online(n)`<br>
**parameter** : 
- `n` (int) : the number you want to search for factor<br>

**output** :
- factor_seq (list of int) : list of the factors of n search from factordb.com<br>
<br>

### decrypt m from p , q
**condition** : know p , q , e , n , c (int)<br>
**function** : `m(int) = rsa_decrypt_from__pq(p,q,e,n,c)`<br>
**parameter** :
- `p` , `q` (int) : the factors of n
- `n` , `e` (int) : parameter of rsa encrypt/decrypt
- `c` (int) : cipher<br>

**output** : 
- `m` (int) : the plain of c<br>
<br>

### extern gcd
**condition** : none<br>
**function** : `(x,y) = extern_gcd(a,b)`<br>
**parameter** : 
- `a` , `b` (int) : the param  of ax + by = gcd(a,b)<br>

**output** :
- `(x,y)` (int) : the solve of ax + by = gcd(a,b)<br>
<br>

### coppersmith short pad
**condition** : if m1 = (2^k)m + r1 , m2 = (2^k)m + r2 and we know m1 and m2's cipher c1 and c2 , and n , e (well the number need to fit the coppersmith method's condition)
**function** : `m1 = coppersmith_short_pad_attack(n,c1,c2,e)`<br>
**parameter**:
- `n` , `e` (int): the RSA encrypt/decrypt param
- `c1` , `c2` (int): the cipher of m1 and m2<br>

**output** :
- `m1` : the plain of c1<br>
<br>

### factor n with d
**condition** : we know n , e , d and e*d = 1 mod phi (well the number need to fit the coppersmith method's condition)<br>
**function** : `p(int) = factor_n_with_d(e,d,n)`<br>
**parameter** : 
- `e` , `d` , `n` (int) : RSA encrypt/decrypt param<br>

**output** :
- `p` (int) : a factor of n<br>
<br>

### franklin reiter
**condition** : we know the form of f which f(m1) = m2 , and know about c1 , c2(cipher of m1 , m2) , e , n (well the number need to fit the coppersmith method's condition)<br>
**function** : `m1(int) = franklin_reiter(n,e,c1,c2,f)`<br>
**parameter** :
- `e` , `n` (int) : RSA encrypt/decrypt param<br>
- `c1` , `c2` (int) : the cipher of m1 , m2
- `f` (polynomial) : f(m1) = m2 , need to put `Z = PolynomialRing(Zmod(n),implementation='NTL', names=('x',)); (x,) = Z._first_ngens(1)` infront of it<br>

**output** : 
- `m1` (int) : the plain of c1<br>
<br>

### known high bits of p
**condition** : we know the high bits of p (called pbar) and n(well the number need to fit the coppersmith method's condition)<br>
**function** : `(p,q) = known_high_bits_of_p(n,pbar)`
**parameter** :
- `n` (int) : the RSA encrypt/decrypt param
- `pbar` (int) : the known high bits of p<br>

**output** :
- (p,q) (int) : the two factors of n<br>
<br>

### LSB oracle attack
**condition** : there's a server recv cipher and sendback the plain(decrypt from cipher)'s lowwest bit and if will give the original cipher of server and n<br>
**function** : `m(int) = LSB_oracle_attack(n,e,c,oracle)`<br>
**parameter** :
- `n` , `e` , `c` (int) : the RSA encrypt/decrypt param (the c is the original cipher)
- `oracle` (func) : input c(int) and send it to server and return lowwest bit of cipher's plain from server<br>

**output** :
- `m` (int) : the plain of original cipher<br>
<br>

### stereotyped message
**condition** : we known about most of m (called mbar) , and c , e , N (well the number need to fit the coppersmith method's condition)<br>
**function** : `x0(int) = stereotyped_message(mbar,c,e,N)`
**parameter** : 
- `c` , `e` , `n` (int): the RSA encrypt/decrypt param
- `mbar` (int): m = mbar + x0<br>

**output** :
- `x0` (int): m = mbar + x0<br>
<br>

### wiener attack
**condition** : d is smaller than some number (acroding to n)<br>
**function** : `m(int) = wiener_attack(n,e,c)`<br>
**parameter** : 
- `n` , `e` , `c` (int) : the RSA encrypt/decrypt param<br>

**output** :
- `m` (int) : the plain of c<br>
<br>

### fermat factor
**condition** : n = p*q and p q is too close<br>
**function** : `(p,q) = fermat_factor(n)`<br>
**parameter** : 
- `n` (int) : the number to factor<br>

**output** :
- `p` , `q` (int) : the factor of n<br>
<br>

### pollard algorithm
**condition** : n = p*q and p's biggest prime factor is realy small<br>
**function** : `p(int) = pollard_algorithm(n)`<br>
**parameter** :
- `n` (int): the number to factor<br>

**output** :
- `p` (int) : the prime factor of n<br>
<br>

### simple factor
**condition** : none<br>
**function** : `p(int) = simple_factor(n)`<br>
**parameter** : 
- `n` (int) : the number to factor<br>

**output** :
- `p` (int) : the prime factor of n<br>
<br>
