import sys
from collections import namedtuple
import random
from enum import Enum
import hashlib
from aes import AES
import lowMCparams

BYTE_SIZE = 8
WORD_SIZE = 64
SALT_SIZE_IN_BITS = 256
NUM_OF_PARTIES = 3

class Version(Enum):
    PICNIC_L1_FS = "picnic-L1-FS"
    PICNIC_L3_FS = "picnic-L3-FS"
    PICNIC_L5_FS = "picnic-L5-FS"

class ChooseHash(Enum):
    SHAKE128 = "SHAKE128"
    SHAKE256 = "SHAKE256"

class Status(Enum):
    VALID = "VALID"
    INVALID = "INVALID"

class View:
    iShare      = None # The input key share of this party, n bits long.
    transcript  = tuple()  # The transcript of all communication during the protocol.
    oShare      = None # The output share of this party, n bits long.

class PICNIC:
    """
        Picnic using fiat-shamir transformation only
        Reference: https://github.com/kenluck2001/cipherResearch/blob/main/references/spec-v3.0-picnic.pdf 
    """
    def __init__(self, version = Version.PICNIC_L1_FS):
        self.version = version
        Param = namedtuple('Param', ['S', 'n', 's', 'r', 'hashOrKDF', 'lH', 'T'])

        # Adding settings
        #paramPerPicnicL1FS  = Param(128, 128, 10, 20, ChooseHash.SHAKE128, 256, 219)
        #modify T atrtributes due to the use of sha512 instead of shake
        paramPerPicnicL1FS  = Param(128, 128, 10, 20, ChooseHash.SHAKE128, 256, 150)
        paramPerPicnicL3FS  = Param(192, 192, 10, 30, ChooseHash.SHAKE256, 384, 329)
        paramPerPicnicL5FS  = Param(256, 256, 10, 38, ChooseHash.SHAKE256, 512, 438)

        self.ParamDict = {
            Version.PICNIC_L1_FS: paramPerPicnicL1FS, 
            Version.PICNIC_L3_FS: paramPerPicnicL3FS, 
            Version.PICNIC_L5_FS: paramPerPicnicL5FS, 
        }

        # add lowMC specific code
        settings = self.ParamDict[self.version]
        n = settings.n
        r = settings.r
        self.lowMcparams = lowMCparams.getLowMCParameter(n, n, r)

    ####################### Routine for text manipulation ###########################

    def ConvertAlphabetsToBinary(self, s1):
        '''
            Convert alphabet to binary
        '''
        asiiLst = [ord(c1) for c1 in s1]
        binString = self.ConvertVecToBinary(asiiLst)
        return binString

    def __ConvertBinaryToVec(self, st, SET_BYTE_SIZE=BYTE_SIZE):
        '''
            Convert binary to ascii code
        '''
        lenOfBinString = len(st)
        quantizedLenOfBinString = ((lenOfBinString // SET_BYTE_SIZE) + 1) * SET_BYTE_SIZE
        numOfBits = quantizedLenOfBinString if (lenOfBinString % SET_BYTE_SIZE) > 0 else lenOfBinString
        quantizedBinString = st.zfill(numOfBits)
        res = []
        for i in range(numOfBits // SET_BYTE_SIZE):
            start, end = i * SET_BYTE_SIZE, (i + 1) * SET_BYTE_SIZE
            curString = quantizedBinString[start: end]
            asciiValue = int(curString, 2)
            res.append(asciiValue)
        return res

    def ConvertBinaryToAlphabet(self, st):
        '''
            Convert binary to alphabet
        '''
        res = self.__ConvertBinaryToVec(st)
        resString = "".join([chr(c1) for c1 in res])
        return resString

    def RightCircularShift(self, string, n):
        '''
            Perform right circular shift
        '''
        return string[-n:] + string[:-n]

    def VectoredXor(self, vec1, vec2):
        return [(int(x) ^ int(y)) for x, y in zip(vec1, vec2)]

    def VectoredAnd(self, vec1, vec2):
        return [(int(x) & int(y)) for x, y in zip(vec1, vec2)]

    def getAlphabetFromBinaryText (self, textBin):
        alphabetString = self.ConvertBinaryToAlphabet(textBin)
        return alphabetString

    def GenerateVecFromText(self, text):
        '''
            Convert alphabet text to vector
        '''
        binString = self.ConvertAlphabetsToBinary(text)
        textVec = self.__ConvertBinaryToVec(binString)
        return textVec

    def GenerateVecFromBinaryText(self, text, SET_BYTE_SIZE=BYTE_SIZE):
        '''
            Convert binary string or binary list to vector
        '''
        if type(text) == list:
            text = "".join([str(w) for w in text])
        textVec = self.__ConvertBinaryToVec(text, SET_BYTE_SIZE=SET_BYTE_SIZE)
        return textVec

    def ConvertVecToBinary(self, res, SET_BYTE_SIZE=BYTE_SIZE):
        resString = "".join([bin(c1)[2:].zfill(SET_BYTE_SIZE) for c1 in res])
        return resString

    def GenerateHexFromBinaryText(self, text):
        '''
            Convert binary string to hexademical string (without 0x prefix)
        '''
        # Use a table for conversion
        table = {
            0 : '0',
            1 : '1',
            2 : '2',
            3 : '3',
            4 : '4',
            5 : '5',
            6 : '6',
            7 : '7',
            8 : '8',
            9 : '9',
            10 : 'a',
            11 : 'b',
            12 : 'c',
            13 : 'd',
            14 : 'e',
            15 : 'f',
        }
        textVec = self.__ConvertBinaryToVec(text, SET_BYTE_SIZE=BYTE_SIZE // 2)
        resString = "".join([table[y] for y in textVec])
        return resString

    def GenerateBinaryTextFromHex(self, text):
        '''
            Convert hexademical string (without 0x prefix) to binary string
        '''
        # Use a table for conversion
        table = {
            '0' : '0000',
            '1' : '0001',
            '2' : '0010',
            '3' : '0011',
            '4' : '0100',
            '5' : '0101',
            '6' : '0110',
            '7' : '0111',
            '8' : '1000',
            '9' : '1001',
            'a' : '1010',
            'b' : '1011',
            'c' : '1100',
            'd' : '1101',
            'e' : '1110',
            'f' : '1111',
        }
        resString = "".join([table[y] for y in text.lower()])
        return resString

    def ConvertAlphabetsToHex (self, text):
        '''
            Convert alphabet to hex string (without 0x prefix)
        '''
        textBin = self.ConvertAlphabetsToBinary(text)
        hexText = self.GenerateHexFromBinaryText(textBin)

        return hexText

    def ConvertHexToAlphabets (self, hexText):
        '''
            Convert hex string (without 0x prefix) to alphabet
        '''
        hexBin = self.GenerateBinaryTextFromHex(hexText)
        alphabets =  self.ConvertBinaryToAlphabet(hexBin)

        return alphabets

    def GenerateVecFromHex(self, text, SET_BYTE_SIZE=BYTE_SIZE):
        '''
            Convert hex string to vector
        '''
        textBin = self.GenerateBinaryTextFromHex(text)
        textVec = self.__ConvertBinaryToVec(textBin, SET_BYTE_SIZE=SET_BYTE_SIZE)
        return textVec

    def GenerateHexFromVec(self, res, SET_BYTE_SIZE=BYTE_SIZE):
        '''
            Convert vec to Hex
        '''
        txtBin = self.ConvertVecToBinary(res, SET_BYTE_SIZE=BYTE_SIZE)
        hexTxt = self.GenerateHexFromBinaryText(txtBin)
        return hexTxt


    def __prepareInputForHash(self, xValHex):
        '''
            convert hex to alphabet strngs before hashing
        '''
        txt = self.ConvertHexToAlphabets(xValHex)
        return txt

    def __prepareInputForCommitment(self, xValHex, view):
        '''
            convert hex to alphabet strngs before hashing
        '''
        xhash = self.__prepareInputForHash(xValHex)
        transcriptString = ""
        if view.transcript:
            transcriptString = "".join([str(w) for w in view.transcript])
        output = "{}{}{}{}".format(xhash, view.iShare, transcriptString, view.oShare)
        return output

    def __getRandomBits(self, length):
        '''
            Get Random bit string of size: length
        '''
        minValue = (1 << (length//2)) - 1
        maxValue = (1 << length) - 1

        rndVal = random.randrange(minValue, maxValue)
        rndBin = bin(rndVal)[2:].zfill(length)

        return rndBin

    def __getRandomAlphabetWords(self, length):
        '''
            Get Random alphabet string of size: length in bits
        '''
        rndBin = self.__getRandomBits(length)
        txt = self.ConvertBinaryToAlphabet(rndBin)

        return txt

    def ConvertByteVecToAlphabet(self, textVec):
        txtBin = self.ConvertVecToBinary(textVec)
        txt = self.ConvertBinaryToAlphabet(txtBin)

        return txt

    ####################### End of Routine for text manipulation ###########################

    ############################### Routine for lowMC ######################################

    def  mpc_sbox (self, state, rand, views):
        '''
            input:
                state: 2D array of bit array matching each shares
                rand: each shares
                views: views of party
            output:
                2D array of bit array of state
        '''
        settings = self.ParamDict[self.version]
        s = settings.s

        a = [0 for _ in range(NUM_OF_PARTIES)]
        b = [0 for _ in range(NUM_OF_PARTIES)]
        c = [0 for _ in range(NUM_OF_PARTIES)]

        for ind in range (0, NUM_OF_PARTIES*s, NUM_OF_PARTIES):
            for j in range(NUM_OF_PARTIES):
                a[j] = state[j][ind + 2]
                b[j] = state[j][ind + 1]
                c[j] = state[j][ind]

            ab = self.mpc_and(a, b, rand, views)
            bc = self.mpc_and(b, c, rand, views)
            ca = self.mpc_and(c, a, rand, views)

            for j in range(NUM_OF_PARTIES):
                state[j][ind + 2] = a[j] ^ bc[j]
                state[j][ind + 1] = a[j] ^ b[j] ^ ca[j]
                state[j][ind] = a[j] ^ b[j] ^ c[j] ^ ab[j]

        return state

    def  mpc_sbox_verify (self, state, rand, views):
        '''
            input:
                state: 2D array of bit array matching each shares
                rand: each shares
                views: views of party
            output:
                2D array of bit array of state
        '''
        settings = self.ParamDict[self.version]
        s = settings.s

        a = [0 for _ in range(NUM_OF_PARTIES - 1)]
        b = [0 for _ in range(NUM_OF_PARTIES - 1)]
        c = [0 for _ in range(NUM_OF_PARTIES - 1)]

        for ind in range (0, NUM_OF_PARTIES*s, NUM_OF_PARTIES):
            for j in range(NUM_OF_PARTIES - 1):
                a[j] = state[j][ind + 2]
                b[j] = state[j][ind + 1]
                c[j] = state[j][ind]

            ab = self.mpc_and_verify(a, b, rand, views)
            bc = self.mpc_and_verify(b, c, rand, views)
            ca = self.mpc_and_verify(c, a, rand, views)

            for j in range(NUM_OF_PARTIES - 1):
                state[j][ind + 2] = a[j] ^ bc[j]
                state[j][ind + 1] = a[j] ^ b[j] ^ ca[j]
                state[j][ind] = a[j] ^ b[j] ^ c[j] ^ ab[j]

        return state

    def mpc_and(self, a, b, rand, views):
        '''
            input:
                a[0..2], b[0..2]
                rand: each shares
                views: views of party
            output:
                c: array
        '''
        r = rand[:] # 3 elements
        c = [None for _ in range(NUM_OF_PARTIES)]
        for i in range(NUM_OF_PARTIES):
            c[i] = ( int(a[i]) & int(b[(i + 1) % NUM_OF_PARTIES])) ^ (int(a[(i + 1) % NUM_OF_PARTIES]) & int(b[i])) ^ (int(a[i]) & int(b[i])) ^ int(r[i], 16) ^ int(r[(i + 1) % NUM_OF_PARTIES], 16)
            views[i].transcript += (c[i],)

        return c

    def mpc_and_verify(self, a, b, rand, views):
        '''
            input:
                a[0..2], b[0..2]
                rand: each shares
                views: views of party
            output:
                c: array
        '''
        r = rand[:] # 2 elements
        c = [None for _ in range(NUM_OF_PARTIES - 1)]
        c[0] = (int(a[0]) & int(b[1])) ^ (int(a[1]) & int(b[0])) ^ (int(a[0]) & int(b[0])) ^ int(r[0], 16) ^ int(r[1], 16)
        views[0].transcript += (c[0],) # update tuple
        c[1] = views[1].transcript[1]

        return c

    def mpc_xor_constant(self, aVec, roundconstantVec):
        '''
            input:
                aVec: n byte array
                roundconstantVec: round contant byte array
            output:
                aVec: array
        '''
        # aVec[0] = aVec[0] XOR roundconstantVec # XOR of L-bit strings
        aVec[0] = self.VectoredXor(aVec[0], roundconstantVec)
        return aVec

    def mpc_xor_constant_verify(self, aVec, roundconstantVec, chal_t ):
        '''
            input:
                aVec: n byte array
                roundconstantVec: round contant byte array
                chal_t: challenge at t
            output:
                res: array
        '''
        if chal_t == 0:
            # aVec[0] = aVec[0] XOR roundconstantVec # XOR of L-bit strings
            aVec[0] = self.VectoredXor(aVec[0], roundconstantVec)
        elif chal_t == 2:
            # aVec[1] = aVec[1] XOR roundconstantVec # XOR of L-bit strings
            aVec[1] = self.VectoredXor(aVec[1], roundconstantVec)

        return aVec

    def mpc_xor(self, aVec, bVec):
        '''
            Input: 
                m bit vectors of length L: aVec[0..m - 1][0..L - 1] and bVec[0..m - 1][0..L
            - 1]
                Output: XOR of the two inputs c[0..m][0..L - 1]
        '''
        m = len(aVec)
        c = [None for _ in range(m)]
        for i in range(m):
            #c[i] = aVec[i] XOR bVec[i] // XOR of L-bit strings
            c[i] = self.VectoredXor(aVec[i], bVec[i])

        return c

    def __matrix_mul(self, x, M):
        '''
            Input: an n-bit vector x, an n-bit by n-bit matrix M
            Output: an n-bit vector a = xM
            (1 X n) (n x m) = (1 x m)
        '''
        n = len(x)
        nmat =  len(M)
        assert n == nmat
        mmat =  len(M[0])
        a = [0 for _ in range(mmat)]
        for i in range(mmat):
            temp = 0
            for j in range(n):
                temp = temp ^ ( int(x[j]) & int(M[i][j]) )
            a[i] = temp
        return a

    def matrix_mul(self, xm, M):
        '''
            Input: an v n-bit vector xm, an n-bit by n-bit matrix M
            Output: an n-bit vector a = xM
            (v X n) (n x m) = (v x m)
        '''
        v = len(xm)
        n = len(xm[0])
        nmat =  len(M)
        assert n == nmat
        mmat =  len(M[0])
        a = [[0]*v for _ in range(v)]
        for i in range(v):
            temp = self.__matrix_mul(xm[i], M)
            a[i] = temp
        return a

    ##################### End of Routine for lowMC ###########################

    ####################### Routine for picnic ###############################

    def GenKeys(self):
        '''
            Generate public and private keys
        '''
        settings = self.ParamDict[self.version]
        n = settings.n
        plainText = self.__getRandomAlphabetWords(n)
        KeyText = self.__getRandomAlphabetWords(n)

        aes = AES()
        cipherText = aes.Encrypt(plainText, KeyText)

        PublicKey = namedtuple('PublicKey', ['cipherText', 'plainText'])
        SecretKey = namedtuple('SecretKey', ['KeyText'])
        CombinedKey = namedtuple('CombinedKey', ['sk', 'pk'])

        # Adding settings
        paramPerSecretKey  = SecretKey(KeyText)
        paramPerPublicKey  = PublicKey(cipherText, plainText)
        paramPerCombinedKey  = CombinedKey(paramPerSecretKey, paramPerPublicKey)

        return paramPerCombinedKey

    def hashfunc (self, index, value, view=None):
        '''
            Generate hash
                input: 
                    index: index for the hash function in use
                    value: hexadecimal string
                output: hexadecimal string (without 0x prefix)
        '''
        hexValue = "0{}{}".format(index, value)
        wordTxt = self.__prepareInputForHash(hexValue)
        if view:
            wordTxt = self.__prepareInputForCommitment(hexValue, view)

        if sys.version_info.major == 3:
            hashVal = hashlib.sha512(wordTxt.encode('utf-8')).hexdigest()
        else:
            hashVal = hashlib.sha512(wordTxt).hexdigest()
        return hashVal

    def __makeSeed(self, sk, pk, text, S):
        '''
            Generate seeds
                input: 
                    sk: private key
                    pk: public key
                    text: message in alphabet textual format
                    S: strength in bits
                output: concatenated seed
        '''
        msgVec = self.GenerateVecFromText(text) # byte array
        msgString = "".join([str(w) for w in msgVec])

        output = "{}{}{}{}{}".format(sk.KeyText, msgString, pk.cipherText, pk.plainText, self.__getRandomAlphabetWords(S))

        return output

    def KDF(self, seed, salt, t, j):
        '''
            Generate KDF hash
                input: 
                    seed: alphabet
                    salt: alphabet
                    t: index for proof repetition
                    j: index for player
                output: hexadecimal hash
        '''
        settings = self.ParamDict[self.version]
        n = settings.n
        s = settings.s
        r = settings.r

        outputLength = n + (NUM_OF_PARTIES * r * s)
        hexTxt = self.ConvertAlphabetsToHex(seed)
        hashVal = self.hashfunc ( 2, hexTxt )
        output = "{}{}{}{}{}".format(hashVal, salt, t, j, outputLength)

        if sys.version_info.major == 3:
            hashVal = hashlib.sha256(output.encode('utf-8')).hexdigest()
        else:
            hashVal = hashlib.sha256(output).hexdigest()

        return hashVal

    def __calculateProof(self, challengeLst, CLst, ViewLst, SeedLst):
        '''
            return a tuple of lists (B list and Z list) of the signature
        '''
        bLst = []
        zLst = []
        T = len (SeedLst)
        for t in range(T):
            ind = (challengeLst[t] + 2) % 3
            bLst.append (CLst[t][ind])
            curZProof = None
            if challengeLst[t] == 0:
                curZProof = (ViewLst[t][1].transcript, SeedLst[t][0], SeedLst[t][1])
                #zLst.append(curZProof)
            elif challengeLst[t] == 1:
                curZProof = (ViewLst[t][2].transcript, SeedLst[t][1], SeedLst[t][0], ViewLst[t][0].iShare)
                #zLst.append(curZProof)
            elif challengeLst[t] == 2:
                curZProof = (ViewLst[t][0].transcript, SeedLst[t][1], SeedLst[t][0], ViewLst[t][1].iShare)
                #zLst.append(curZProof)
            zLst.append(curZProof)

        return bLst, zLst

    def __isSignatureEqual(self, signature, otherSignature):
        challengeLst, otherChallengeLst = signature.e, otherSignature.e
        salt, otherSalt = signature.salt, otherSignature.salt
        bLst, otherBLst = signature.b, otherSignature.b
        zLst, otherZLst = signature.z, otherSignature.z

        intersect = set(challengeLst) & set(otherChallengeLst)
        isChallengeEq = ((len(intersect) == len(set(challengeLst))) and (len(intersect) == len(set(otherChallengeLst))))

        isSaltEq = (salt == otherSalt)

        intersect = set(bLst) & set(otherBLst)
        isBLstEq = ((len(intersect) == len(set(bLst))) and (len(intersect) == len(set(otherBLst))))

        intersect = set(zLst) & set(otherZLst)
        isZLstEq = ((len(intersect) == len(set(zLst))) and (len(intersect) == len(set(otherZLst))))

        return isChallengeEq and isSaltEq and isBLstEq and isZLstEq

    def __isChallengeValid(self, challengeLst, otherChallengeLst):
        for chal, ochal in zip(challengeLst, otherChallengeLst):
            if chal != ochal:
                return False

        return True

    def __prepareInputForChallenge(self, ViewLst, CLst, pk, salt, text):
        '''
            Generate challenge
                input: 
                    ViewLst: views of every player across every proof ( T x number of parties)
                    CLst: commitment of every player across every proof ( T x number of parties)
                    pk: public key
                    salt: random value
                    text: message in alphabet textual format
                output: concatenated string
        '''
        settings = self.ParamDict[self.version]
        T = settings.T

        flattenLst = lambda res : "".join([str(w) for w in res])

        if hasattr(ViewLst[0][0], 'oShare') and ViewLst[0][0].oShare is not None:
            viewString = "".join([flattenLst(ViewLst[t][i].oShare) for t in range(T) for i in range(NUM_OF_PARTIES)])
        else:
            viewString = "".join([flattenLst(ViewLst[t][i]) for t in range(T) for i in range(NUM_OF_PARTIES)])

        comString = "".join([CLst[t][i] for t in range(T) for i in range(NUM_OF_PARTIES)])
        msgVec = self.GenerateVecFromText(text) # byte array
        msgString = "".join([str(w) for w in msgVec])

        output = "{}{}{}{}".format(viewString, comString, salt, pk.cipherText, pk.plainText, msgString)

        return output

    def HashChallenge(self, ViewLst, CLst, pk, salt, text):
        '''
            it is hash3
        '''
        msg = self.__prepareInputForChallenge(ViewLst, CLst, pk, salt, text)
        hexTxt = self.ConvertAlphabetsToHex(msg)
        hashHex = self.hashfunc (1, hexTxt)
        T = len(ViewLst)
        eLst = []
        hexBin = self.GenerateBinaryTextFromHex(hashHex)

        evenIndLst = [y for x, y in enumerate(hexBin) if x%2==0]
        oddIndLst  = [y for x, y in enumerate(hexBin) if x%2==1]

        for x, y in zip (evenIndLst, oddIndLst):
            if (x, y) == ('0', '0'):
                eLst.append (0)
            elif (x, y) == ('0', '1'):
                eLst.append (1)
            elif (x, y) == ('1', '0'):
                eLst.append (2)

        print ("length of challenge: {}".format(len(eLst)))
        # ensure that the challenge matchs the proof. Extra tweak that is outside the specs
        eLst = eLst[:T]
        return eLst

    def HashChallenge2(self, ViewLst, CLst, pk, salt, text):
        '''
            This will work only with SHAKE, not sha256 with is outputs 128 bits
            it is hash3
        '''
        msg = self.__prepareInputForChallenge(ViewLst, CLst, pk, salt, text)
        hexTxt = self.ConvertAlphabetsToHex(msg)
        hashHex = self.hashfunc (1, hexTxt)
        T = len(ViewLst)
        eLst = []
        while True:
            hexBin = self.GenerateBinaryTextFromHex(hashHex)

            evenIndLst = [y for x, y in enumerate(hexBin) if x%2==0]
            oddIndLst  = [y for x, y in enumerate(hexBin) if x%2==1]

            for x, y in zip (evenIndLst, oddIndLst):
                if (x, y) == ('0', '0'):
                    eLst.append (0)
                elif (x, y) == ('0', '1'):
                    eLst.append (1)
                elif (x, y) == ('1', '0'):
                    eLst.append (2)

            if len(eLst) == T:
                break
            else:
                eLst = [] # empty list
            hashHex = self.hashfunc (1, hashHex)

        return eLst

    def Sign(self, sk, pk, text):
        '''
            input: 
                sk: secret key
                pk: public key
                text: message in alphabet textual format
            output: Signature on M which consist of (challenge and proof).
        '''
        settings = self.ParamDict[self.version]
        S = settings.S
        T = settings.T
        n = settings.n
        r = settings.r

        # 256-bit salt value salt.
        salt = self.__getRandomAlphabetWords(SALT_SIZE_IN_BITS)

        # listy of views
        ViewLst = [ [View()]*NUM_OF_PARTIES for _ in range(T) ]
        # list of commitments
        CLst = [[0]*NUM_OF_PARTIES for _ in range(T)]
        # list of seeds
        SeedLst = [ [self.__makeSeed(sk, pk, text, S)]*NUM_OF_PARTIES for _ in range(T) ]

        xVal = [0 for _ in range (NUM_OF_PARTIES)]
        rand = [0 for _ in range (NUM_OF_PARTIES)]

        Lmatrix = self.lowMcparams.LinearLayerMatrix #    LinearLayerMatrix.size: 20x128x128
        Kmatrix = self.lowMcparams.RoundKeyMatrix    #    RoundKeyMatrix.size: 21x128x128
        roundconstant = self.lowMcparams.RoundConstants #    RoundConstants.size: 20x128

        for t in range(T):

            for j in range(NUM_OF_PARTIES):
                rand[j] = self.KDF(SeedLst[t][j], salt, t, j)

            # hexadecimal values are 4 bits per character
            share0Hex = rand[0][: n//4] # first n bits of tape rand[0]
            share1Hex = rand[1][: n//4] # first n bits of tape rand[1]

            share0Vec = self.GenerateVecFromHex(share0Hex)
            share1Vec = self.GenerateVecFromHex(share1Hex)

            combShares01Vec = self.VectoredXor(share0Vec, share1Vec)
            secretVec = self.GenerateVecFromText(sk.KeyText)
            share2Vec = self.VectoredXor(secretVec, combShares01Vec)

            xVal[0] = share0Vec
            xVal[1] = share1Vec
            xVal[2] = share2Vec

            # encryption flow

            xValBits = [self.ConvertVecToBinary(x) for x in xVal]
            key = self.matrix_mul(xValBits, Kmatrix[0])
            plainTextBin = self.ConvertAlphabetsToBinary(pk.plainText)
            state = self.mpc_xor_constant(key, plainTextBin)
            
            #print ("state: {}".format(state))

            views = ViewLst[t]
            for i in range(1, r+1):
                key = self.matrix_mul(xValBits, Kmatrix[i])
                state = self.mpc_sbox(state, rand, views )
                state = self.matrix_mul(state, Lmatrix[i-1])
                state = self.mpc_xor_constant(state, roundconstant[i-1])
                state = self.mpc_xor(state, key)

            ViewLst[t] = views

            for i in range (NUM_OF_PARTIES):
                ViewLst[t][i].iShare = xVal[i]
                ViewLst[t][i].oShare = self.GenerateVecFromBinaryText(state[i])

            # calculate the commitment
            for i in range (NUM_OF_PARTIES):
                hexTxt = self.ConvertAlphabetsToHex(SeedLst[t][i])
                hashHex = self.hashfunc (4, hexTxt)
                CLst[t][i] = self.hashfunc (0, hashHex, view=ViewLst[t][i])

        # calculate the challenge
        challengeLst = self.HashChallenge(ViewLst, CLst, pk, salt, text)

        bLst, zLst = self.__calculateProof(challengeLst, CLst, ViewLst, SeedLst)
        Signature = namedtuple('Signature', ['e', 'salt', 'b', 'z'])
        #e: challenge
        #b: part of proof
        #z: part of proof

        signature  = Signature(challengeLst, salt, bLst, zLst)
        return signature

    def Verify(self, signature, pk, text):

        settings = self.ParamDict[self.version]
        S = settings.S
        T = settings.T
        n = settings.n
        r = settings.r

        challengeLst = signature.e
        salt = signature.salt
        bLst = signature.b
        zLst = signature.z

        # listy of views
        ViewLst = [ [View()]*NUM_OF_PARTIES for _ in range(T) ]
        # list of commitments
        CLst = [[0]*NUM_OF_PARTIES for _ in range(T)]
        # list of seeds
        SeedLst = [ [0]*NUM_OF_PARTIES for _ in range(T) ]

        OutputLst = [ [0]*NUM_OF_PARTIES for _ in range(T) ]

        xVal = [0 for _ in range (NUM_OF_PARTIES - 1)]
        rand = [0 for _ in range (NUM_OF_PARTIES - 1)]
        shareVec =[None  for j in range(NUM_OF_PARTIES - 1)]

        Lmatrix = self.lowMcparams.LinearLayerMatrix #    LinearLayerMatrix.size: 20x128x128
        Kmatrix = self.lowMcparams.RoundKeyMatrix    #    RoundKeyMatrix.size: 21x128x128
        roundconstant = self.lowMcparams.RoundConstants #    RoundConstants.size: 20x128

        for t in range(T):
            curZProof = zLst[t]
            if challengeLst[t] == 0:
                (ViewLst[t][1].transcript, SeedLst[t][0], SeedLst[t][1]) = curZProof
            elif challengeLst[t] == 1:
                (ViewLst[t][2].transcript, SeedLst[t][1], SeedLst[t][0], ViewLst[t][0].iShare) = curZProof
            elif challengeLst[t] == 2:
                (ViewLst[t][0].transcript, SeedLst[t][1], SeedLst[t][0], ViewLst[t][1].iShare) = curZProof

            for j in range(NUM_OF_PARTIES - 1):
                rand[j] = self.KDF(SeedLst[t][j], salt, t, j)

            for j in range(NUM_OF_PARTIES - 1):
                # hexadecimal values are 4 bits per character
                share0Hex = rand[j][: n//4] # first n bits of tape rand[j]
                shareVec[j] = self.GenerateVecFromHex(share0Hex)

            xVal[0] = shareVec[0]
            xVal[1] = shareVec[1]

            xValBits = [self.ConvertVecToBinary(x) for x in xVal]

            plainTextBin = self.ConvertAlphabetsToBinary(pk.plainText)
            key = self.matrix_mul(xValBits, Kmatrix[0])

            state = self.mpc_xor_constant_verify(key, plainTextBin, challengeLst[t])

            views = ViewLst[t]
            for i in range(1, r+1):
                key = self.matrix_mul(xValBits, Kmatrix[i])
                state = self.mpc_sbox_verify(state, rand, views )
                state = self.matrix_mul(state, Lmatrix[i-1])
                state = self.mpc_xor_constant_verify(state, roundconstant[i-1], challengeLst[t] )
                state = self.mpc_xor(state, key)

            ViewLst[t] = views

            ViewLst[t][0].oShare = self.GenerateVecFromBinaryText(state[0])
            ViewLst[t][1].oShare = self.GenerateVecFromBinaryText(state[1])

            # calculate the commitment
            hexTxt = self.ConvertAlphabetsToHex(SeedLst[t][0])
            hashHex = self.hashfunc (4, hexTxt)
            CLst[t][challengeLst[t]] = self.hashfunc (0, hashHex, view=ViewLst[t][0])

            hexTxt = self.ConvertAlphabetsToHex(SeedLst[t][1])
            hashHex = self.hashfunc (4, hexTxt)
            CLst[t][(challengeLst[t] + 1) % NUM_OF_PARTIES] = self.hashfunc (0, hashHex, view=ViewLst[t][1])
            CLst[t][(challengeLst[t] + 2) % NUM_OF_PARTIES] = bLst[t]

            # TODO: THERE IS A BUG AROUND HERE. NOT YET SURE.
            OutputLst[t][challengeLst[t]] = ViewLst[t][0].oShare
            OutputLst[t][(challengeLst[t] + 1) % NUM_OF_PARTIES] = ViewLst[t][1].oShare

            combShares01Vec = self.VectoredXor(ViewLst[t][0].oShare, ViewLst[t][1].oShare)
            cipherTextVec = self.GenerateVecFromText(pk.cipherText) 

            OutputLst[t][(challengeLst[t] + 2) % NUM_OF_PARTIES] = self.VectoredXor(cipherTextVec, combShares01Vec)

        # calculate the challenge
        otherChallengeLst = self.HashChallenge(OutputLst, CLst, pk, salt, text)

        print ("len(challengeLst): {}, challengeLst: {}, len(otherChallengeLst): {}, otherChallengeLst: {}".format(len(challengeLst), challengeLst, len(otherChallengeLst), otherChallengeLst))
        if self.__isChallengeValid(challengeLst, otherChallengeLst):
            return Status.VALID.value
        return Status.INVALID.value

    ####################### End of Routine for picnic ###############################

if __name__ == '__main__':
    picnic = PICNIC()
    key = picnic.GenKeys()
    print ("key object: {}".format(key))
    print ("secret key KeyText: {}".format(key.sk.KeyText))
    print ("public key plainText: {}".format(key.pk.plainText))
    print ("public key cipherText: {}".format(key.pk.cipherText))

    msg = "KENNETH IS A GREAT MAN THAT HAS LOTS OF ACCOMPLISMENTS"
    signature = picnic.Sign(key.sk, key.pk, msg)

    status = picnic.Verify(signature, key.pk, msg)
    print ("signature status: {}".format(status))

