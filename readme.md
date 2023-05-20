# Cryptography Experiments

This is where I put some quick dirty implementations of a few cryptographic cipher. This is strictly for learning purposes and show not be used in production.
No attempting was made to perform constant-time cryptography, so timing attack abound in our implementation.

Read about the implementation decisions in blog.
Link: https://kenluck2001.github.io/blog_post/probing_real-world_cryptosystems.html

The following cryptographic ciphers are implemented:
- AES (128 bits, 192 bits, 256 bits)
- DES
- Ascon
- Picnic

The following modes are currently supported.
- ECB
- CBC

# File structure
+ /src
    - This contains the implementations of the cipher, key exchanges, and other protocols
+ /references
    - Papers that described the algorithm

This is an educational pursuit. Thanks.
