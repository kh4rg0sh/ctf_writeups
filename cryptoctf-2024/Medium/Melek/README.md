# Melek [66 solves]
### Challenge Description
> Melek is a secret sharing scheme that may be relatively straightforward to break - what are your thoughts on the best way to approach it?
# Challenge Files
`melek.sage`
```python
#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag

def encrypt(msg, nbit):
	m, p = bytes_to_long(msg), getPrime(nbit)
	assert m < p
	e, t = randint(1, p - 1), randint(1, nbit - 1)
	C = [randint(0, p - 1) for _ in range(t - 1)] + [pow(m, e, p)]
	R.<x> = GF(p)[]
	f = R(0)
	for i in range(t): f += x**(t - i - 1) * C[i]
	P = [list(range(nbit))]
	shuffle(P)
	P = P[:t]
	PT = [(a, f(a)) for a in [randint(1, p - 1) for _ in range(t)]]
	return e, p, PT

nbit = 512
enc = encrypt(flag, nbit)
print(f'enc = {enc}')
```
`output.txt`
```txt
enc = <REDACTED DUE TO HUGE SIZE>
```

# Solution
We shall start analysing the encryption method first.
```py
def encrypt(msg, nbit):
	m, p = bytes_to_long(msg), getPrime(nbit)
	assert m < p
	e, t = randint(1, p - 1), randint(1, nbit - 1)
	C = [randint(0, p - 1) for _ in range(t - 1)] + [pow(m, e, p)]
	R.<x> = GF(p)[]
	f = R(0)
	for i in range(t): f += x**(t - i - 1) * C[i]
	P = [list(range(nbit))]
	shuffle(P)
	P = P[:t]
	PT = [(a, f(a)) for a in [randint(1, p - 1) for _ in range(t)]]
	return e, p, PT

nbit = 512
enc = encrypt(flag, nbit)
print(f'enc = {enc}')
```
From the above snippet of code, we know that `p` is a `512` bit prime and `e` is a random integer in the range $[1, p - 1]$ and both of these integers are a public knowledge
```py
e = 3316473234742974510609176519968107496789324827839883341690084725836178910956015867823194881383215644380418162164089588828798132617649547462723383625707014
p = 9486915681801496583557174944405629563403346572353787092582704754226121096049954529719556720667960706741084895049852989479773192757968901195529919070579679
```
Next, we observe that the plaintext is being encrypted and appended to the list `C`
```py
C = [randint(0, p - 1) for _ in range(t - 1)] + [pow(m, e, p)]
```
and in the rest of the code, it shuffles the list `C`, generates a polynomial of degree `t - 1` and provides us with `t` points on the 2D-plot of this polynomial. We are interested in the constant term of this polynomial (as that's our encrypted plaintext). Hence, if we could recover the polynomial from the given shares, then we would be done. This is, however, a standard task using Lagrange's Interpolation.
## Lagrange's Interpolation on Finite Fields
One might expect that the next step is to code up the interpolation formula, but since this is already implemented in sagemath. We shall directly use that!
```python
shares = <REDACTED DUE TO SIZE>
F = GF(p)
R = F['x']
f = R.lagrange_polynomial(shares)

c = int(f(0))
```
and we can easily get the constant term of the polynomial by evaluating it at zero! The next step is to perform modular inverse of $m^e \pmod{p}$ to compute $m$. But if you try to do that directly, we get the following `ValueError`:
```bash
fooker@fooker:~/cryptoctf2024/melek$ python3 solve.py
Traceback (most recent call last):
  File "/home/fooker/cryptoctf2024/melek/solve.py", line 15, in <module>
    print(long_to_bytes(pow(c, (pow(e, -1, (p - 1))), p)))
ValueError: base is not invertible for the given modulus
fooker@fooker:~/cryptoctf2024/melek$
```
and the reason for that is
```bash
fooker@fooker:~/cryptoctf2024/melek$ python3
Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> e = 3316473234742974510609176519968107496789324827839883341690084725836178910956015867823194881383215644380418162164089588828798132617649547462723383625707014
>>> p = 9486915681801496583557174944405629563403346572353787092582704754226121096049954529719556720667960706741084895049852989479773192757968901195529919070579679
>>> from math import gcd
>>> print(gcd(e, p - 1))
2
>>>
```
## RSA non-Coprime Exponent Decryption
the first step is to realise that we can still compute $m^2 \pmod{p}$ using the textbook RSA decryption algorithm, since
$$
c \equiv \left(m^{\gcd(e, p - 1)}\right)^{\tfrac{p - 1}{\gcd(e, p - 1)}} \pmod{p}
$$
and $\gcd\left(\frac{p - 1}{\gcd(e, p - 1)}, p - 1\right) = 1$. In the next step, we could observe that $p \equiv 3 \pmod{4}$. Therefore, computing the $\frac{(p + 1)}{4}$ th power of $m^2 \pmod{p}$ would yield
$$
\left(m^2\right)^{\tfrac{p + 1}{4}} \equiv m^{\tfrac{p + 1}{2}} \equiv m^{\tfrac{p - 1}{2}} m \equiv \pm m \pmod{p}
$$
and we can recover the plaintext.
## Solve Script
`solve.py`
```py
from sage.all import *
from Crypto.Util.number import *

e = 3316473234742974510609176519968107496789324827839883341690084725836178910956015867823194881383215644380418162164089588828798132617649547462723383625707014
p = 9486915681801496583557174944405629563403346572353787092582704754226121096049954529719556720667960706741084895049852989479773192757968901195529919070579679

shares = <REDACTED DUE TO SIZE>

F = GF(p)
R = F['x']
f = R.lagrange_polynomial(shares)

c = int(f(0))

c2 = pow(c, (pow((e // 2), -1, (p - 1))), p)
print(long_to_bytes(pow(c2, (p + 1) // 4, p)))
```
and that gives us the flag
```bash
fooker@fooker:~/cryptoctf2024/melek$ python3 solve.py
b'CCTF{SSS_iZ_4n_3fF!ciEn7_5ecr3T_ShArIn9_alGorItHm!}'
fooker@fooker:~/cryptoctf2024/melek$
```

