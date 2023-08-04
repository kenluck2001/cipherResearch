# Cryptography Experiments

This is the implementation of Tortoise. We support none-respecting and nonce-misuse resistant modes in our AEAD scheme.
No attempting was made to perform constant-time cryptography, so timing attack abound in our implementation.

Solutions tested on on Python 2.7.16 and VirtualEnv is used to make environment reproducible.

## How to run
+ Setup environment
```
virtualenv -p /usr/bin/python py2env
source py2env/bin/activate
pip install -r requirements.txt
```
+ Executing from command line
```
python tortoise-respecting.py
python tortoise-resistant.py
```

