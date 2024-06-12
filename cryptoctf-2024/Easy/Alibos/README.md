# Alibos [181 solves]
### Challenge Description
> Alibos, a classic cryptographic algorithm, is designed to safeguard non-sensitive data, providing a reliable solution for routine information protection.
# Challenge Files
`alibos.py`
```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from gmpy2 import *
from secret import d, flag

get_context().precision = 1337

def pad(m, d):
	if len(str(m)) < d:
		m = str(m) + '1' * (d - len(str(m)))
	return int(m)

def genkey(d):
	skey = getRandomRange(10 ** (d - 1), 10 ** d)
	pkey = int(10**d * (sqrt(skey) - floor(sqrt(skey))))
	return pkey, skey

def encrypt(m, pkey):
	m = pad(m, len(str(pkey)))
	d = len(str(pkey))
	c = (pkey + d ** 2 * m) % (10 ** d)
	return c

pkey, skey = genkey(d)

m = bytes_to_long(flag)
c = encrypt(m, pkey)

print(f'pkey = {pkey}')
print(f'enc  = {c}')
```
`output.txt`
```txt
pkey = 8582435512564229286688465405009040056856016872134514945016805951785759509953023638490767572236748566493023965794194297026085882082781147026501124183913218900918532638964014591302221504335115379744625749001902791287122243760312557423006862735120339132655680911213722073949690947638446354528576541717311700749946777
enc  = 6314597738211377086770535291073179315279171595861180001679392971498929017818237394074266448467963648845725270238638741470530326527225591470945568628357663345362977083408459035746665948779559824189070193446347235731566688204757001867451307179564783577100125355658166518394135392082890798973020986161756145194380336
```

# Solution
We shall begin by analysing the challenge files first. We are provided with the public key `pkey` and the encrypted message `enc` and we would like to retrieve the plaintext `m`. If we take a closer look at the encryption method.
```python
def encrypt(m, pkey):
	m = pad(m, len(str(pkey)))
	d = len(str(pkey))
	c = (pkey + d ** 2 * m) % (10 ** d)
	return c
```
We notice that the encryption algorithm is easily reversible if we can know the hidden parameter `d`. However, `d = len(str(pkey))` and we know `pkey`. So we can easily know the value for `d` and decrypt the ciphertext.
## Decryption
Let's first state the decryption algorithm. We are moving stuff around to compute `m`. Hence,
$$
\left(\text{c} - \text{pkey}\right) \cdot d^{-2} \equiv m \pmod{10^d}
$$
This could be implemented as
```python
d = len(str(pkey))
m = ((enc - pkey) * (pow(d ** 2, -1, 10 ** d))) % (10 ** d)
```
## Unpadding
Before we could transform the plaintext `m` into something readable, we would have to get rid of the padding in the plaintext. 
```python
def pad(m, d):
	if len(str(m)) < d:
		m = str(m) + '1' * (d - len(str(m)))
	return int(m)
```
This snippet of code tells us that our message is being padded by a lot of `1`s. We could get rid of these `1`s by parsing the integer as a string and stripping off the trailing `1`s and transforming the remainder integer back to bytes
## Solve Script
`solve.py`
```python
from Crypto.Util.number import *

pkey = 8582435512564229286688465405009040056856016872134514945016805951785759509953023638490767572236748566493023965794194297026085882082781147026501124183913218900918532638964014591302221504335115379744625749001902791287122243760312557423006862735120339132655680911213722073949690947638446354528576541717311700749946777
enc  = 6314597738211377086770535291073179315279171595861180001679392971498929017818237394074266448467963648845725270238638741470530326527225591470945568628357663345362977083408459035746665948779559824189070193446347235731566688204757001867451307179564783577100125355658166518394135392082890798973020986161756145194380336

d = len(str(pkey))

print(long_to_bytes(int(str(((enc - pkey) * (pow(d ** 2, -1, 10 ** d))) % (10 ** d)).rstrip('1'))))
```
and that gives us the flag 
```bash
fooker@fooker:~/cryptoctf2024/alibos/$ python3 solve.py
b'CCTF{h0M3_m4De_cRyp70_5ySTeM_1N_CryptoCTF!!!}'
fooker@fooker:~/cryptoctf2024/alibos/$
```
