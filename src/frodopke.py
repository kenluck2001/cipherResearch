"""
Adapted from the KEM implementation in https://github.com/microsoft/PQCrypto-LWEKE/blob/master/python3/frodokem.py. I have reformulated the code example to handle public key encryption of froDOKEM post quantum cipher. Most of the existing codes are retained and partly refactored, However, I added the following methods:
- encrypt
- decrypt

After consistent failure in my implementation due to endian mismatch. I abandoned this code snippet ( https://github.com/kenluck2001/cipherResearch/blob/main/src/frodo.py ). The refactored code has better secure primitives that make more production-ready cryptography library as part of my investigation. I am trying out professional open source modules to see how things are done in the proper way. This works only for Python 3
"""
import bitstring
import math
#import secrets
# secrets module requires openssl, so I replaced with a less secure random module for experimental purposes.
import random as secrets
import struct
import warnings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class FrodoKPE(object):
    '''
        FrodoKPE implementation
        Refrerence: https://frodokem.org/files/FrodoKEM-specification-20171130.pdf
    '''

    def __init__(self, variant = "FrodoKEM-640-AES"):
        """Construct a new FrodoKEM instance
        
        - variant: One of FrodoKEM-{640,976,1344}-{AES,SHAKE}"""
        self.print_intermediate_values = False
        self.variant = variant
        #self.randombytes = lambda k : bytes((secrets.randbits(8) for i in range(k)))
        self.randombytes = lambda k : bytes((secrets.getrandbits(8) for i in range(k)))

        print ("FrodoKPE in use: {}".format(variant))
        if variant == "FrodoKEM-640-AES":
            self.setParamsFrodo640()
            self.gen = self.genAES128
        elif variant == "FrodoKEM-640-SHAKE":
            self.setParamsFrodo640()
            self.gen = self.genSHAKE128
        elif variant == "FrodoKEM-976-AES":
            self.setParamsFrodo976()
            self.gen = self.genAES128
        elif variant == "FrodoKEM-976-SHAKE":
            self.setParamsFrodo976()
            self.gen = self.genSHAKE128
        elif variant == "FrodoKEM-1344-AES":
            self.setParamsFrodo1344()
            self.gen = self.genAES128
        elif variant == "FrodoKEM-1344-SHAKE":
            self.setParamsFrodo1344()
            self.gen = self.genSHAKE128
        else:
            assert "Unknown variant"

    def setParamsFrodo640(self):
        """Set the parameters for Frodo640"""
        # FrodoKEM specification, Table 3
        self.error_distribution = (9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1)
        self.T_chi = FrodoKPE.__cdf_zero_centred_symmetric(self.error_distribution)
        # FrodoKEM specification, Table 4
        self.D = 15
        self.q = 32768
        self.n = 640
        self.nbar = 8
        self.mbar = 8
        self.B = 2
        self.len_seedA = 128
        self.len_z = 128
        self.len_mu = 128
        self.len_seedSE = 128
        self.len_s = 128
        self.len_k = 128
        self.len_pkh = 128
        self.len_ss = 128
        self.len_chi = 16
        self.len_seedA_bytes = int(self.len_seedA / 8)
        self.len_z_bytes = int(self.len_z / 8)
        self.len_mu_bytes = int(self.len_mu / 8)
        self.len_seedSE_bytes = int(self.len_seedSE / 8)
        self.len_s_bytes = int(self.len_s / 8)
        self.len_k_bytes = int(self.len_k / 8)
        self.len_pkh_bytes = int(self.len_pkh / 8)
        self.len_ss_bytes = int(self.len_ss / 8)
        self.len_chi_bytes = int(self.len_chi / 8)
        self.shake = FrodoKPE.__shake128
        # FrodoKEM specification, Table 5
        self.len_sk_bytes = 19888
        self.len_pk_bytes = 9616
        self.len_ct_bytes = 9720
        self.len_ss_bytes = 16

    def setParamsFrodo976(self):
        """Set the parameters for Frodo976"""
        # FrodoKEM specification, Table 3
        self.error_distribution = (11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1)
        self.T_chi = FrodoKPE.__cdf_zero_centred_symmetric(self.error_distribution)
        # FrodoKEM specification, Table 4
        self.D = 16
        self.q = 65536
        self.n = 976
        self.nbar = 8
        self.mbar = 8
        self.B = 3
        self.len_seedA = 128
        self.len_z = 128
        self.len_mu = 192
        self.len_seedSE = 192
        self.len_s = 192
        self.len_k = 192
        self.len_pkh = 192
        self.len_ss = 192
        self.len_chi = 16
        self.len_seedA_bytes = int(self.len_seedA / 8)
        self.len_z_bytes = int(self.len_z / 8)
        self.len_mu_bytes = int(self.len_mu / 8)
        self.len_seedSE_bytes = int(self.len_seedSE / 8)
        self.len_s_bytes = int(self.len_s / 8)
        self.len_k_bytes = int(self.len_k / 8)
        self.len_pkh_bytes = int(self.len_pkh / 8)
        self.len_ss_bytes = int(self.len_ss / 8)
        self.len_chi_bytes = int(self.len_chi / 8)
        self.shake = FrodoKPE.__shake256
        # FrodoKEM specification, Table 5
        self.len_sk_bytes = 31296
        self.len_pk_bytes = 15632
        self.len_ct_bytes = 15744
        self.len_ss_bytes = 24

    def setParamsFrodo1344(self):
        """Set the parameters for Frodo1344"""
        # FrodoKEM specification, Table 3
        self.error_distribution = (18286, 14320, 6876, 2023, 364, 40, 2)
        self.T_chi = FrodoKPE.__cdf_zero_centred_symmetric(self.error_distribution)
        # FrodoKEM specification, Table 4
        self.D = 16
        self.q = 65536
        self.n = 1344
        self.nbar = 8
        self.mbar = 8
        self.B = 4
        self.len_seedA = 128
        self.len_z = 128
        self.len_mu = 256
        self.len_seedSE = 256
        self.len_s = 256
        self.len_k = 256
        self.len_pkh = 256
        self.len_ss = 256
        self.len_chi = 16
        self.len_seedA_bytes = int(self.len_seedA / 8)
        self.len_z_bytes = int(self.len_z / 8)
        self.len_mu_bytes = int(self.len_mu / 8)
        self.len_seedSE_bytes = int(self.len_seedSE / 8)
        self.len_s_bytes = int(self.len_s / 8)
        self.len_k_bytes = int(self.len_k / 8)
        self.len_pkh_bytes = int(self.len_pkh / 8)
        self.len_ss_bytes = int(self.len_ss / 8)
        self.len_chi_bytes = int(self.len_chi / 8)
        self.shake = FrodoKPE.__shake256
        # FrodoKEM specification, Table 5
        self.len_sk_bytes = 43088
        self.len_pk_bytes = 21520
        self.len_ct_bytes = 21632
        self.len_ss_bytes = 32

    def __print_intermediate_value(self, name, value):
        """Prints an intermediate value for debugging purposes"""
        if not(self.print_intermediate_values): return None
        if isinstance(value, bytes):
            print("{:s} ({:d}) = {:s}".format(name, len(value), value.hex().upper()))
        elif name in ["r"]:
            print("{:s} ({:d}) = ".format(name, len(value)), end='')
            for i in range(len(value)):
                print("{:d},".format(value[i] % self.q), end='')
            print()
        elif name in ["A", "B", "B'", "B''", "B'S", "C", "C'", "E", "E'", "E''", "M", "S", "S'", "S^T", "V", "mu_encoded"]:
            print("{:s} ({:d} x {:d}) = ".format(name, len(value), len(value[0])), end='')
            for i in range(len(value)):
                for j in range(len(value[0])):
                    print("{:d},".format(value[i][j] % self.q), end='')
            print()
        else:
            assert False, "Unknown value type for " + name

    @staticmethod
    def __shake128(msg, digest_len):
        """Returns a bytes object containing the SHAKE-128 hash of msg with 
        digest_len bytes of output"""
        shake_ctx = hashes.Hash(hashes.SHAKE128(digest_len), backend = default_backend())
        shake_ctx.update(msg)
        return shake_ctx.finalize()

    @staticmethod
    def __shake256(msg, digest_len):
        """Returns a bytes object containing the SHAKE-256 hash of msg with 
        digest_len bytes of output"""
        shake_ctx = hashes.Hash(hashes.SHAKE256(digest_len), backend = default_backend())
        shake_ctx.update(msg)
        return shake_ctx.finalize()

    @staticmethod
    def __aes128_16bytesonly(key, msg):
        """Returns a bytes object containing the AES-128 encryption of the 16-byte 
        message msg using the given key"""
        cipher_ctx = Cipher(algorithms.AES(key), modes.ECB(), backend = default_backend())
        encryptor_ctx = cipher_ctx.encryptor()
        return encryptor_ctx.update(msg) + encryptor_ctx.finalize()

    @staticmethod
    def __cdf_zero_centred_symmetric(chi):
        """Converts a table of the form given in FrodoKEM specification Table 3 to 
        a zero-centred CDF suitable for sampling using a uniform random value.
        Assumes that chi is given in multiples of 2^{len_chi}. Based on equations
        for T_chi(0) and T_chi(z) in FrodoKEM specification Section 2.2.4."""
        T_chi = list(range(len(chi)))
        T_chi[0] = int(chi[0] / 2) - 1
        for z in range(1, len(chi)):
            T_chi[z] = T_chi[0] + sum(chi[1:z + 1])
        return T_chi

    def __matrix_mul(self, X, Y):
        """Compute matrix multiplication X * Y mod q"""
        nrows_X = len(X)
        ncols_X = len(X[0])
        nrows_Y = len(Y)
        ncols_Y = len(Y[0])
        assert ncols_X == nrows_Y, "Mismatched matrix dimensions"
        R = [[0 for j in range(ncols_Y)] for i in range(nrows_X)]
        for i in range(nrows_X):
            for j in range(ncols_Y):
                for k in range(ncols_X):
                    R[i][j] += X[i][k] * Y[k][j]
                R[i][j] %= self.q
        return R

    def __matrix_add(self, X, Y):
        """Compute matrix addition X + Y mod q"""
        nrows_X = len(X)
        ncols_X = len(X[0])
        nrows_Y = len(Y)
        ncols_Y = len(Y[0])
        assert ncols_X == ncols_Y and nrows_X == nrows_Y, "Mismatched matrix dimensions"
        return [[(X[i][j] + Y[i][j]) % self.q for j in range(ncols_X)] for i in range(nrows_X)]

    def __matrix_sub(self, X, Y):
        """Compute matrix subtraction X - Y mod q"""
        nrows_X = len(X)
        ncols_X = len(X[0])
        nrows_Y = len(Y)
        ncols_Y = len(Y[0])
        assert ncols_X == ncols_Y and nrows_X == nrows_Y, "Mismatched matrix dimensions"
        return [[(X[i][j] - Y[i][j]) % self.q for j in range(ncols_X)] for i in range(nrows_X)]
    
    def __matrix_transpose(self, X):
        """Compute transpose of matrix X"""
        nrows = len(X)
        ncols = len(X[0])
        return [[X[j][i] for j in range(nrows)] for i in range(ncols)]

    @staticmethod
    def __bytes_to_bit_array(B):
        """Convert a byte array in little-endian format to a little-endian bit 
        array"""
        b = bitstring.BitArray(length=8*len(B))
        for i in range(len(B)):
            for l in range(8):
                b.set((B[i] >> l) % 2, 8*i+l)
        return b

    @staticmethod
    def __ctverify(a, b):
        """Compares two equal-length matrices of integers; returns True if equal, False if any element differs.
        
        For a secure implementation, this method must be implemented in constant-time. While 
        the Python code here is similar to a typical constant-time implementation in C, the
        internal representation of integers in implementations of Python means that this 
        method may not be constant-time."""
        r = 0
        for i in range(len(a)):
            for j in range(len(a[i])):
                r = r | (a[i][j] ^ b[i][j])
        return r == 0

    @staticmethod
    def __ctselect(a, b, selector):
        """Select one of two equal-length byte arrays. If selector True, use a, else use b."""
        mask = 0
        for i in range(8):
            mask = mask | (selector << i)
        r = bytearray()
        for i in range(len(a)):
            r.append((a[i] & mask) | (b[i] & ~mask))
        return bytes(r)
    
    def encode(self, k):
        """Encode a bitstring (represented in Python as a bytes object) as a mod-q 
        integer matrix (FrodoKEM specification, Algorithm 1)"""
        l = self.B * self.mbar * self.nbar
        K = [[0 for j in range(self.nbar)] for i in range(self.mbar)]
        kbits = FrodoKPE.__bytes_to_bit_array(k)
        # 1. for i = 0; i < mbar; i += 1
        for i in range(self.mbar):
            # 2. for j = 0; j < nbar; j += 1
            for j in range(self.nbar):
                # 3. tmp = sum_{l=0}^{B-1} k_{(i*nbar+j)*B+l} 2^l
                tmp = 0
                for l in range(self.B):
                    if kbits[(i * self.nbar + j) * self.B + l]: tmp += 2 ** l
                # 4. K[i][j] = ec(tmp) = tmp * q/2^B
                K[i][j] = tmp * int(self.q / (2 ** self.B))
        return K
    
    @staticmethod
    def __bit_array_to_bytes(b):
        """Convert a little-endian bit array to a byte array in little-endian format"""
        B = bytearray(int(len(b)/8))
        for i in range(len(B)):
            for l in range(8):
                if b[8*i+l]: B[i] |= 1 << l
        return bytes(B)
    
    def decode(self, K):
        """Decode a mod-q integer matrix into a bitstring (represented in Python 
        as a bytes object) (FrodoKEM specification, Algorithm 2)"""
        k = bitstring.BitArray(length=self.B * self.mbar * self.nbar)
        # 1. for i = 0; i < mbar; i += 1
        for i in range(self.mbar):
            # 2. for j = 0; j < nbar; j += 1
            for j in range(self.nbar):
                # 3. tmp = dc(K[i][j]) = round(K[i][j] * 2^B / q) mod 2^B
                # Note that round is defined (as in FrodoKEM specification, Section 2.1.1) as
                #     round(x) = floor(x + 1/2)
                # The native implementation using floating point arithmentic and the round function
                #     tmp = round(K[i][j] * (2 ** self.B) / self.q) % (2 ** self.B)
                # should not be used because floating point rounding rules are not quite the same
                # (IEEE 754 rounds ties to even, i.e., half integers round to the closest even number).
                # Either of the following two lines produce correct results.
                #     3.a) tmp = floor(K[i][j] * 2^B / q + 0.5) mod 2^B
                tmp = math.floor(K[i][j] * (2 ** self.B) / self.q + 0.5) % (2 ** self.B)
                #     3.b) tmp = (((K[i][j] << 2^B) + 2^(D-1)) >> D) mod 2^B, where q = 2^D
                #tmp = (((K[i][j] << self.B) + 2 ** (self.D - 1)) >> self.D) % (2 ** self.B)
                # 4. tmp' = sum_{l=0}^{B-1} tmp_l * 2^l
                tmpbits = [0 for l in range(self.B)]
                for l in range(self.B):
                    tmpbits[l] = tmp % 2
                    tmp >>= 1
                # 5. for l = 0; l < B; l += 1
                for l in range(self.B):
                    # 6. k[(i*nbar+j)*B+l] = tmpbits[l]
                    k.set(tmpbits[l], (i * self.nbar + j) * self.B + l)
        return FrodoKPE.__bit_array_to_bytes(k)

    def pack(self, C):
        """Pack a matrix mod q into a bitstring (represented in Python as a bytes 
        object) (FrodoKEM specification, Algorithm 3)"""
        n1 = len(C)
        n2 = len(C[0])
        b = bitstring.BitArray(self.D * n1 * n2)
        # 1. for i = 0; i < n1; i += 1
        for i in range(n1):
            # for j = 0; j < n2; j += 1
            for j in range(n2):
                # 3. Cij = sum_{l=0}^{D-1} c_l * 2^l
                tmp = C[i][j]
                c = [0 for l in range(self.D)]
                for l in range(self.D):
                    c[l] = tmp % 2
                    tmp >>= 1
                # 4. for l = 0; l < D; L += 1
                for l in range(self.D):
                    # 5. b[(i * n2 + j) * D + l] = c[D - 1 - l]
                    b[(i * n2 + j) * self.D + l] = c[self.D - 1 - l]
        return b.bytes
    
    def unpack(self, b, n1, n2):
        """Unpack a bitstring (represented in Python as a bytes object) into a 
        matrix mod q (FrodoKEM specification, Algorithm 4)"""
        C = [[0 for j in range(n2)] for i in range(n1)]
        bbits = bitstring.Bits(b)
        # 1. for i = 0; i < n1; i += 1
        for i in range(n1):
            # 2. for j = 0; j < n2; j += 1
            for j in range(n2):
                # 3. Cij = sum_{l=0}^{D-1} b_{(i*n2+j)*D+l} * 2^{D-1-l}
                for l in range(self.D):
                    if bbits[(i * n2 + j) * self.D + l]: C[i][j] += 2 ** (self.D - 1 - l)
        return C

    def sample(self, r):
        """Sample from the error distribution using noise r (a two-byte array 
        encoding a 16-bit integer in little-endian byte order) (FrodoKEM 
        specification, Algorithm 5)"""
        # 1. t = sum_{i=1}^{len_x - 1} r_i * 2^{i-1}
        t = r >> 1
        # 2. e = 0
        e = 0
        # 3. for z = 0; z < s; z += 1
        for z in range(len(self.T_chi) - 1):
            # 4. if t > T_chi(z)
            if t > self.T_chi[z]:
                # 5. e = e + 1
                e += 1
        # 6. e = (-1)^{r_0} * e
        r0 = r % 2
        e = ((-1) ** r0) * e
        return e

    def sample_matrix(self, r, n1, n2):
        """Sample an n1 x n2 matrix from the error distribution using noise r 
        (FrodoKEM specification, Algorithm 6)"""
        E = [[None for j in range(n2)] for i in range(n1)]
        # 1. for i = 0; i < n1; i += 1
        for i in range(n1):
            # 2. for j = 0; j < n2; j += 1
            for j in range(n2):
                # 3. E[i][j] = Frodo.Sample(r^{i*n2+j}, T_chi)
                E[i][j] = self.sample(r[i * n2 + j])
        return E

    def genAES128(self, seedA):
        """Generate matrix A using AES-128 (FrodoKEM specification, Algorithm 7)"""
        A = [[None for j in range(self.n)] for i in range(self.n)]
        # 1. for i = 0; i < n; i += 1
        for i in range(self.n):
            # 2. for j = 0; j < n; j += 8
            for j in range(0, self.n, 8):
                # 3. b = i || j || 0 || ... || 0 in {0,1}^128, where i and j are encoded as 16-bit integers in little-endian byte order
                b = bytearray(16)
                struct.pack_into('<H', b, 0, i)
                struct.pack_into('<H', b, 2, j)
                # 4. c = AES128(seedA, b)
                c = FrodoKPE.__aes128_16bytesonly(seedA, b)
                # 5. for k = 0; k < 8; k += 1
                for k in range(8):
                    # 6. A[i][j+k] = c[k] where c is treated as a sequence of 8 16-bit integers each in little-endian byte order
                    A[i][j + k] = struct.unpack_from('<H', c, 2 * k)[0] % self.q
        return A

    def genSHAKE128(self, seedA):
        """Generate matrix A using SHAKE-128 (FrodoKEM specification, Algorithm 8)"""
        A = [[None for j in range(self.n)] for i in range(self.n)]
        # 1. for i = 0; i < n; i += 1
        for i in range(self.n):
            # 2. b = i || seedA in {0,1}^{16 + len_seedA}, where i is encoded as a 16-bit integer in little-endian byte order
            tmp = bytearray(2)
            struct.pack_into('<H', tmp, 0, i)
            b = tmp + seedA
            # 3. c_{i,0} || c_{i,1} || ... || c_{i,n-1} = SHAKE128(b, 16n) (length in bits) where each c_{i,j} is parsed as a 16-bit integer in little-endian byte order format
            tmp = FrodoKPE.__shake128(b, int(16 * self.n / 8))
            c_i = [struct.unpack_from('<H', tmp, 2 * j)[0] for j in range(self.n)]
            # 4. for j = 0; j < n; j +=1
            for j in range(self.n):
                # 5. A[i][j] = c[i][j] mod q
                A[i][j] = c_i[j] % self.q
        return A

    def keygen(self):
        seedA = self.randombytes(self.len_seedA_bytes)
        seedSE = self.randombytes(self.len_s_bytes)
        A = self.gen(seedA)
        rbytes = self.shake(bytes(b'\x5f') + seedSE, 2 * self.n * self.nbar * self.len_chi_bytes)
        r = [struct.unpack_from('<H', rbytes, 2*i)[0] for i in range(2 * self.n * self.nbar)]
        self.__print_intermediate_value("r", r)
        # S^T = Frodo.SampleMatrix(r[0 .. n*nbar-1], nbar, n)
        Stransposed = self.sample_matrix(r[0 : self.n * self.nbar], self.nbar, self.n)
        self.__print_intermediate_value("S^T", Stransposed)
        S = self.__matrix_transpose(Stransposed)
        # E = Frodo.SampleMatrix(r[n*nbar .. 2*n*nbar-1], n, nbar)
        E = self.sample_matrix(r[self.n * self.nbar : 2 * self.n * self.nbar], self.n, self.nbar)
        # B = A S + E
        B = self.__matrix_add(self.__matrix_mul(A, S), E)
        self.__print_intermediate_value("B", B)
        b = self.pack(B)
        pk = seedA + b
        sk = self.pack(S)

        sk = bitstring.BitArray()
        for i in range(self.nbar):
            for j in range(self.n):
                sk.append(bitstring.BitArray(intle = Stransposed[i][j], length = 16))
        sk = sk.bytes

        return (pk, sk)

    def encrypt(self, plainText, pk):
        '''
            input:
                mu: string in plaintext
                pk: public key
            output: ciphertext
        '''
        # TODo: fix message bit encoding 
        mu = plainText
        seedA = pk[0 : self.len_seedA_bytes]
        b = pk[self.len_seedA_bytes : ]
        seedSE = self.randombytes(self.len_s_bytes)
        # r = SHAKE(0x96 || seedSE, 2*mbar*n + mbar*nbar*len_chi) (length in bits)
        rbytes = self.shake(bytes(b'\x96') + seedSE, (2 * self.mbar * self.n + self.mbar * self.nbar) * self.len_chi_bytes)
        r = [struct.unpack_from('<H', rbytes, 2*i)[0] for i in range(2 * self.mbar * self.n + self.mbar * self.nbar)]
        self.__print_intermediate_value("r", r)
        # S' = Frodo.SampleMatrix(r[0 .. mbar*n-1], mbar, n)
        Sprime = self.sample_matrix(r[0 : self.mbar * self.n], self.mbar, self.n)
        self.__print_intermediate_value("S'", Sprime)
        # E' = Frodo.SampleMatrix(r[mbar*n .. 2*mbar*n-1], mbar, n)
        Eprime = self.sample_matrix(r[self.mbar * self.n : 2 * self.mbar * self.n], self.mbar, self.n)
        self.__print_intermediate_value("E'", Eprime)
        # A = Frodo.Gen(seedA)
        A = self.gen(seedA)
        # 8. B' = S' A + E'
        Bprime = self.__matrix_add(self.__matrix_mul(Sprime, A), Eprime)
        c1 = self.pack(Bprime)
        Eprimeprime = self.sample_matrix(r[2 * self.mbar * self.n : 2 * self.mbar * self.n + self.mbar * self.nbar], self.mbar, self.nbar)
        self.__print_intermediate_value("E''", Eprimeprime)
        B = self.unpack(b, self.n, self.nbar)
        self.__print_intermediate_value("B", B)
        V = self.__matrix_add(self.__matrix_mul(Sprime, B), Eprimeprime)
        self.__print_intermediate_value("V", V)
        C = self.__matrix_add(V, self.encode(mu))
        self.__print_intermediate_value("C", C)
        c2 = self.pack(C)
        self.__print_intermediate_value("c2", c2)
        ct = c1 + c2
        assert len(ct) == self.len_ct_bytes

        return ct

    def Decrypt(self, ct, sk):
        offset = 0; length = int(self.mbar * self.n * self.D / 8)
        c1 = ct[offset: length]
        self.__print_intermediate_value("c1", c1)
        offset += length; length = int(self.mbar * self.nbar * self.D / 8)
        c2 = ct[offset: offset+length]
        self.__print_intermediate_value("c2", c2)

        Sbytes = bitstring.ConstBitStream(sk)
        Stransposed = [[0 for j in range(self.n)] for i in range(self.nbar)]
        for i in range(self.nbar):
            for j in range(self.n):
                Stransposed[i][j] = Sbytes.read('intle:16')

        S = self.__matrix_transpose(Stransposed)

        C1 = self.unpack(c1, self.mbar, self.n)
        C2 = self.unpack(c2, self.mbar, self.nbar)

        # M = C2 - C1 S
        M = self.__matrix_sub(C2, self.__matrix_mul(C1, S))
        self.__print_intermediate_value("M", M)
        # mu' = Frodo.Decode(M)
        muprime = self.decode(M)

        return muprime

if __name__ == '__main__':
    frodo = FrodoKPE()
    pk, sk = frodo.keygen()
    print ("################################")
    print ("################################")
    msg = frodo.randombytes(frodo.len_mu_bytes)
    cipherText = frodo.encrypt(msg, pk)
    print ("cipherText: {}".format(cipherText))

    decrypted = frodo.Decrypt(cipherText, sk)
    print ("original msg: {}\ndecrypted msg: {}".format(msg, decrypted))

    print ("################################")
    print ("################################")
    frodo = FrodoKPE(variant = "FrodoKEM-640-SHAKE")
    pk, sk = frodo.keygen()
    msg = frodo.randombytes(frodo.len_mu_bytes)
    cipherText = frodo.encrypt(msg, pk)
    print ("cipherText: {}".format(cipherText))

    decrypted = frodo.Decrypt(cipherText, sk)
    print ("original msg: {}\ndecrypted msg: {}".format(msg, decrypted))

    print ("################################")
    print ("################################")
    frodo = FrodoKPE(variant = "FrodoKEM-976-AES")
    pk, sk = frodo.keygen()

    msg = frodo.randombytes(frodo.len_mu_bytes)
    cipherText = frodo.encrypt(msg, pk)
    print ("cipherText: {}".format(cipherText))

    decrypted = frodo.Decrypt(cipherText, sk)
    print ("original msg: {}\ndecrypted msg: {}".format(msg, decrypted))

    print ("################################")
    print ("################################")
    frodo = FrodoKPE(variant = "FrodoKEM-976-SHAKE")
    pk, sk = frodo.keygen()

    msg = frodo.randombytes(frodo.len_mu_bytes)
    cipherText = frodo.encrypt(msg, pk)
    print ("cipherText: {}".format(cipherText))

    decrypted = frodo.Decrypt(cipherText, sk)
    print ("original msg: {}\ndecrypted msg: {}".format(msg, decrypted))

    print ("################################")
    print ("################################")
    frodo = FrodoKPE(variant = "FrodoKEM-1344-AES")
    pk, sk = frodo.keygen()

    msg = frodo.randombytes(frodo.len_mu_bytes)
    cipherText = frodo.encrypt(msg, pk)
    print ("cipherText: {}".format(cipherText))

    decrypted = frodo.Decrypt(cipherText, sk)
    print ("original msg: {}\ndecrypted msg: {}".format(msg, decrypted))

    print ("################################")
    print ("################################")
    frodo = FrodoKPE(variant = "FrodoKEM-1344-SHAKE")
    pk, sk = frodo.keygen()

    msg = frodo.randombytes(frodo.len_mu_bytes)
    cipherText = frodo.encrypt(msg, pk)
    print ("cipherText: {}".format(cipherText))

    decrypted = frodo.Decrypt(cipherText, sk)
    print ("original msg: {}\ndecrypted msg: {}".format(msg, decrypted))
