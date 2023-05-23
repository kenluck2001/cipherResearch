from collections import namedtuple
import random
from enum import Enum
from aes import AES, Version as aesVersion
import math
from keccak import Shake128
import numpy as np
import struct

BYTE_SIZE = 8

class Version(Enum):
    FRODO_640 = "FRODO_640"
    FRODO_976 = "FRODO_976"
    FRODO_1344 = "FRODO_1344"

class Mode(Enum):
    ECB = "ECB"
    CBC = "CBC"

class FRODO:
    """
        Frodokem implementation
        Refrerence: https://frodokem.org/files/FrodoKEM-specification-20171130.pdf

        There is a bug in the implementation that is preventing me from decrypting encrypted messages. It may be due to mismatch of endiannes ( big and little endianess)
    """
    def __init__(self, version = Version.FRODO_640, mode = Mode.ECB):
        self.version = version
        self.mode = mode
        Param = namedtuple('Param', ['n', 'q', 'sigma', 'B', 'hatm', 'hatn', 's', 'aes'])

        # Adding settings
        aes = AES()
        paramPerFrodo640   = Param(640, 1<<15, 2.8, 2, 8, 8, 12, aes)

        aes = AES(version=aesVersion.V192)
        paramPerFrodo976   = Param(976, 1<<16, 2.3, 3, 8, 8, 10, aes)

        aes = AES(version=aesVersion.V256)
        paramPerFrodo1344 = Param(1344, 1<<16, 1.4, 4, 8, 8, 6, aes)

        self.ParamDict = {
            Version.FRODO_640: paramPerFrodo640, 
            Version.FRODO_976: paramPerFrodo976, 
            Version.FRODO_1344: paramPerFrodo1344, 
        }

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

    def __padUsingPKCV7(self, text):
        settings = self.ParamDict[self.version]
        hatm = settings.hatm
        hatn = settings.hatn
        B = settings.B

        characterCount = B * hatm * hatn // 8
        text = text[: characterCount]
        msgSize = len(text)
        if msgSize == characterCount:
            return text
        text = "{}{}".format(text, "\x04"*(characterCount - msgSize))
        print ("t####################\n text: {} \n####################\n".format(text))
        return text

    ####################### End of Routine for text manipulation ###########################

    ####################### Routine for frodo ###############################

    def __ec(self, k):
        settings = self.ParamDict[self.version]
        q = settings.q
        B = settings.B
        res = (k * q) // (1 << B)
        return res

    def __dc(self, c):
        settings = self.ParamDict[self.version]
        q = settings.q
        B = settings.B
        num = (c * (1 << B) // q)
        num = num % (1 << B)

        return num

    def FrodoEncode(self, kBin):
        '''
            input: kBin is length of B x hatm x hatn
            output: matrix of hatm x hatn
        '''
        settings = self.ParamDict[self.version]
        hatm = settings.hatm
        hatn = settings.hatn
        B = settings.B

        kLst = [int(x) for x in kBin]

        kMat = [ [0]*hatn for _ in range(hatm) ]

        for i in range(hatm):
            for j in range(hatn):
                k = 0
                for l in range(B):
                    ind = (((i*hatn) + j)*B) + l
                    k += (kLst[ind] * (1<<l))
                kMat[i][j] = self.__ec(k)

        return kMat

    def FrodoDecode(self, kMat):
        '''
            input: kMat matrix of hatm x hatn
            output: kBin is length of B x hatm x hatn
        '''
        settings = self.ParamDict[self.version]
        hatm = settings.hatm
        hatn = settings.hatn
        B = settings.B

        bLen = B * hatm * hatn
        kLst = [0 for _ in range(bLen)]

        for i in range(hatm):
            for j in range(hatn):
                kVal = self.__dc(kMat[i][j])
                kValBin = bin(kVal)[2:].zfill(B)[::-1]

                for l in range(B):
                    ind = (((i*hatn) + j)*B) + l
                    kLst[ind] = kValBin[l]

        kBin = "".join(kLst)
        return kBin

    def __normalDistPDF(self, x):
        settings = self.ParamDict[self.version]
        sigma = settings.sigma
        var = (sigma)**2
        denom = (2*math.pi*var)**.5
        num = math.exp(-(x**2)/(2*var))
        return num/denom

    def ErrorSampingTable (self):
        '''
            calculate cumulative distribution function
            return a dict of error distribution on a set of supports
        '''
        settings = self.ParamDict[self.version]
        s = settings.s
        #lenX = 2 * s
        lenX = 16

        outputDict = {x:0 for x in range(s+1) }
        outputDict[0] = ((1<<(lenX - 1)) * self.__normalDistPDF(0)) - 1

        cumDict = {x:0 for x in range(s+1) }

        # calculate cumulate density function only
        for x in range(1, s+1):
            cumDict[x] += self.__normalDistPDF(x)

        # calculate error density function only
        for x in range(1, s+1):
            outputDict[x] = ((1<<lenX) * cumDict[x]) + outputDict[0]
        
        return outputDict

    def FrodoSample (self, rBin):
        '''
            input: rBin bit string of lenX
            output: error in decimal
        '''
        tDict = self.ErrorSampingTable()
        settings = self.ParamDict[self.version]
        s = settings.s
        #lenX = 2 * s
        lenX = 16        
        tVal, eVal = 0, 0
        rLst = [int(x) for x in rBin]
        for i in range(1, lenX):
            tVal += ( rLst[i] * (1 << (i-1)) )

        for z in range(s):
            if tVal > tDict[z]:
                eVal += 1

        eVal = ((-1) ** rLst[0]) * eVal

        return eVal

    def FrodoSampleMatrix (self, rBin, n1, n2):
        '''
            input: 
                rBin bit string of n1 * n2 * lenX
            output: error matrix (n1 x n2)
        '''
        settings = self.ParamDict[self.version]
        s = settings.s
        #lenX = 2 * s
        lenX = 16

        eMat = [ [0]*n2 for _ in range(n1) ]

        numOfBits = len(rBin)

        rBinLst = []
        for i in range(numOfBits // lenX):
            start, end = i * lenX, (i + 1) * lenX
            rBinLst.append (rBin[start: end])

        for i in range(n1):
            for j in range(n2):
                ind = (i * n2) + j
                eMat[i][j] = self.FrodoSample (rBinLst[ind])

        return eMat

    """
    def FrodoGen (self, seedA):
        '''
            input: 
                seedA bit string of lenSeed in alphabet
            output: error matrix (n x n)
        '''
        settings = self.ParamDict[self.version]
        n = settings.n
        q = settings.q
        aes = settings.aes

        aMat = [ [0]*n for _ in range(n) ]

        for i in range(0, n):
            for j in range(0, n, 8):
                # Attempt to do computation in little endian
                # This flow is faulty because mismatch in the internals of AES encrypt
                bBin = "{}{}{}".format(bin(i)[2:].zfill(16)[::-1], bin(j)[2:].zfill(16)[::-1], "0"*96)
                #bBin = "{}{}{}".format(bin(i)[2:].zfill(16), bin(j)[2:].zfill(16), "0"*96)
                bText = self.getAlphabetFromBinaryText (bBin)
                cipherText = aes.Encrypt(bText, seedA)
                cipherBin = self.ConvertAlphabetsToBinary(cipherText)
                
                for k in range(0, 8):
                    start, end = k * 16, (k + 1) * 16
                    curVal = int (cipherBin[start: end][::-1], 2)
                    aMat[i][j+k] = curVal % q

        return aMat
    """

    def FrodoGen (self, seedA):
        '''
            input: 
                seedA bit string of lenSeed in alphabet
            output: error matrix (n x n)
        '''
        settings = self.ParamDict[self.version]
        n = settings.n
        q = settings.q
        aes = settings.aes

        aMat = [ [0]*n for _ in range(n) ]

        hashSize = 16 * n // 8 # size in bytes

        for i in range(0, n):
            bBin = "{}{}".format(bin(i)[2:].zfill(16)[::-1], self.ConvertAlphabetsToBinary(seedA))
            hashTxt = self.getAlphabetFromBinaryText(bBin)
            hashHex = Shake128().update(hashTxt).hexdigest(hashSize) 

            cipherBin = self.GenerateBinaryTextFromHex(hashHex)    
            for j in range(0, n):
                start, end = j * 16, (j + 1) * 16
                curVal = int (cipherBin[start: end], 2)
                aMat[i][j] = curVal % q

        return aMat

    def FrodoPKEKeyGen (self):
        settings = self.ParamDict[self.version]
        hatm = settings.hatm
        hatn = settings.hatn
        B = settings.B
        n = settings.n
        s = settings.s
        q = settings.q
        #lenX = 2 * s
        lenX = 16
        bLen = B * hatm * hatn

        seedA = self.__getRandomAlphabetWords(bLen)
        # create matrix
        aMat = self.FrodoGen (seedA)
    
        # create random error seed
        seedSE = self.__getRandomAlphabetWords(bLen)

        # create random bit string
        bBin = "{}{}".format(self.GenerateBinaryTextFromHex("5f"), self.ConvertAlphabetsToBinary(seedSE))
        hashTxt = self.getAlphabetFromBinaryText(bBin)
        hashSize = 2 * n * hatn * lenX // 8 # size in bytes
        hashHex = Shake128().update(hashTxt).hexdigest(hashSize) 

        hBin = self.GenerateBinaryTextFromHex(hashHex)

        sMat = self.FrodoSampleMatrix (hBin[ :(n * hatn * lenX)], hatn, n)
        eMat = self.FrodoSampleMatrix (hBin[(n * hatn * lenX): ], n, hatn)

        aMat = np.asarray(aMat)
        sMat = np.asarray(sMat)
        eMat = np.asarray(eMat)

        bMat = np.matmul(aMat, sMat.T) + eMat
        
        PublicKey = namedtuple('PublicKey', ['seed', 'bMat'])
        SecretKey = namedtuple('SecretKey', ['sMat'])
        CombinedKey = namedtuple('CombinedKey', ['sk', 'pk'])

        # Adding settings
        bMat = bMat % q
        sMat = sMat % q

        bMat = bMat.astype(np.int64)
        sMat = sMat.astype(np.int64)

        paramPerPublicKey  = PublicKey(seedA, bMat)
        paramPerSecretKey  = SecretKey(sMat)
        paramPerCombinedKey  = CombinedKey(paramPerSecretKey, paramPerPublicKey)

        return paramPerCombinedKey

    def Encrypt(self, plainText, pk):
        '''
            input: 
                pk: public key
                plainText: message in alphabet textual format of B * hatm * hatn bits
            output: cipherText
        '''
        settings = self.ParamDict[self.version]
        hatm = settings.hatm
        hatn = settings.hatn
        B = settings.B
        n = settings.n
        s = settings.s
        q = settings.q
        #lenX = 2 * s
        lenX = 16

        paddedMsgTxt = self.__padUsingPKCV7(plainText)
        msgBin = self.ConvertAlphabetsToBinary(paddedMsgTxt)

        bLen = 2 * hatm * hatn
        # random seed
        seedA = pk.seed

        # create matrix
        aMat = self.FrodoGen (seedA)
        # create random error seed
        seedSE = self.__getRandomAlphabetWords(bLen)

        # create random bit string
        bBin = "{}{}".format(self.GenerateBinaryTextFromHex("96"), self.ConvertAlphabetsToBinary(seedSE))
        hashTxt = self.getAlphabetFromBinaryText(bBin)

        hashSize = ((2 * hatm * n) + (hatm * hatn)) * lenX // 8 # size in bytes
        hashHex = Shake128().update(hashTxt).hexdigest(hashSize) 

        hBin = self.GenerateBinaryTextFromHex(hashHex)

        sHatMat = self.FrodoSampleMatrix (hBin[ : (hatm * n * lenX)], hatm, n)
        eHatMat = self.FrodoSampleMatrix (hBin[(hatm * n * lenX) : (2 * hatm * n * lenX)], hatm, n)
        eHatHatMat = self.FrodoSampleMatrix (hBin[(2 * hatm * n * lenX) : ], hatm, hatn)

        sHatMat = np.asarray(sHatMat)
        eHatMat = np.asarray(eHatMat)
        eHatHatMat = np.asarray(eHatHatMat)

        bMat = pk.bMat

        bHatMat = np.matmul(sHatMat, aMat) + eHatMat
        vMat = np.matmul(sHatMat, bMat) + eHatHatMat

        kMat = self.FrodoEncode(msgBin)
        kMat = np.asarray(kMat)

        CipherText = namedtuple('CipherText', ['C1', 'C2'])

        c1Mat = bHatMat % q
        c2Mat = (vMat + kMat) % q

        c1Mat = c1Mat.astype(np.int64)
        c2Mat = c2Mat.astype(np.int64)

        cipherText  = CipherText(c1Mat, c2Mat)

        return cipherText

    def Decrypt(self, cipherText, sk):
        '''
            input: 
                cipherText: cipherText object having c1, c2 of dimension (hatm x n) and (hatm x hatn) respectively.
                plainText: message in alphabet textual format of B * hatm * hatn bits
            output: plaintext in alphabets
        '''
        c1Mat = cipherText.C1
        c2Mat = cipherText.C2
        sMat = sk.sMat

        print ("c1Mat.shape: {}, c2Mat.shape: {}, sMat.shape: {}".format(c1Mat.shape, c2Mat.shape, sMat.shape))

        # c1Mat.shape: (8, 640), c2Mat.shape: (8, 8), sMat.shape: (8, 640)

        mMat = c2Mat - np.matmul(c1Mat, sMat.T)

        msgBin = self.FrodoDecode(mMat)
        msginAlphabets = self.ConvertBinaryToAlphabet(msgBin)

        return msginAlphabets

    ####################### End of Routine for frodo ###############################

    def Cipher(self, plainText, KeyText, initVectorString=None):
        '''
            Encryption on group of blocks
        '''
        settings = self.ParamDict[self.version]
        hatm = settings.hatm
        hatn = settings.hatn
        B = settings.B

        MSG_SIZE_IN_CHARS = B * hatm * hatn // 8
        if self.mode is not Mode.ECB and self.mode is not Mode.CBC:
            raise NotImplementedError("{} is not yet supported".format(self.mode.name))
        # waste 16 bytes before the message
        plainText = "{}{}".format("\x00"*MSG_SIZE_IN_CHARS, plainText) if self.mode is Mode.CBC else plainText
        lenOfBinString = len(plainText) 
        quantizedLenOfString = ((lenOfBinString // MSG_SIZE_IN_CHARS)+1) * MSG_SIZE_IN_CHARS
        numOfBits = quantizedLenOfString if (lenOfBinString % MSG_SIZE_IN_CHARS) > 0 else lenOfBinString
        paddedString = "{}{}".format(plainText, "\x04"*(numOfBits - lenOfBinString))
        if initVectorString:
            initVectorString = "{}{}".format(initVectorString, "\x04"*(MSG_SIZE_IN_CHARS - len(initVectorString)))
            initVectorString = initVectorString[:MSG_SIZE_IN_CHARS]
        paddedString = paddedString[:numOfBits]
        NUM_OF_MESSAGE_BLOCKS = numOfBits // MSG_SIZE_IN_CHARS
        cipherList = [initVectorString]

        # Logic for ECB
        if self.mode is Mode.ECB:
            for i in range (0, NUM_OF_MESSAGE_BLOCKS):
                start, end = i * MSG_SIZE_IN_CHARS, (i + 1) * MSG_SIZE_IN_CHARS
                curPlainText = paddedString[start : end]
                cipherText = self.Encrypt(curPlainText, KeyText)
                cipherList.append(cipherText)
            resString = "".join([c1 for c1 in cipherList[1:]])
            return resString

        # Logic for CBC
        for i in range (1, NUM_OF_MESSAGE_BLOCKS):
            start, end = i * MSG_SIZE_IN_CHARS, (i + 1) * MSG_SIZE_IN_CHARS
            curPlainText = paddedString[start : end]
            prevCipherText = cipherList[i - 1]

            curPlainTextVec = self.__ConvertAlphabetToAsciiCodeList(curPlainText)
            prevCipherTextVec = self.__ConvertAlphabetToAsciiCodeList(prevCipherText)

            yWordVec = self.VectoredXor(curPlainTextVec, prevCipherTextVec)
            yWord = self.__ConvertAsciiListToAlphabet(yWordVec)
            cipherText = self.Encrypt(yWord, KeyText)

            cipherList.append(cipherText)

        resString = "".join([c1 for c1 in cipherList[1:]])
        return resString

    def InvCipher(self, cipherText, KeyText, initVectorString=None):
        '''
            Decryption on group of blocks
        '''
        settings = self.ParamDict[self.version]
        hatm = settings.hatm
        hatn = settings.hatn
        B = settings.B

        MSG_SIZE_IN_CHARS = B * hatm * hatn // 8
        if self.mode is not Mode.ECB and self.mode is not Mode.CBC:
            raise NotImplementedError("{} is not yet supported".format(self.mode.name))
        if initVectorString:
            initVectorString = "{}{}".format(initVectorString, "\x04"*(MSG_SIZE_IN_CHARS - len(initVectorString)))
            initVectorString = initVectorString[:MSG_SIZE_IN_CHARS]
        cipherTextwithoutInitVec = cipherText
        cipherText = "{}{}".format(initVectorString, cipherText) if self.mode is Mode.CBC and initVectorString is not None else cipherTextwithoutInitVec
        lenOfBinString = len(cipherText) 
        quantizedLenOfBinString = ((lenOfBinString // MSG_SIZE_IN_CHARS)+1) * MSG_SIZE_IN_CHARS
        numOfBits = quantizedLenOfBinString if (lenOfBinString % MSG_SIZE_IN_CHARS) > 0 else lenOfBinString

        paddedString = "{}{}".format(cipherText, "\x04"*(numOfBits - lenOfBinString))
        paddedString = paddedString[:numOfBits]

        NUM_OF_MESSAGE_BLOCKS = numOfBits // MSG_SIZE_IN_CHARS
        plainList = []

        # Logic for ECB
        if self.mode is Mode.ECB:
            for i in range (0, NUM_OF_MESSAGE_BLOCKS):
                start, end = i * MSG_SIZE_IN_CHARS, (i + 1) * MSG_SIZE_IN_CHARS
                curCipherText = paddedString[start : end]
                plainText = self.Decrypt(curCipherText, KeyText)
                plainList.append(plainText)
            resString = "".join([c1 for c1 in plainList])
            return resString

        # Logic for CBC
        for i in range (1, NUM_OF_MESSAGE_BLOCKS):
            start, end = i * MSG_SIZE_IN_CHARS, (i + 1) * MSG_SIZE_IN_CHARS
            curCipherText = paddedString[start : end]
            prevStart, prevEnd = (i-1) * MSG_SIZE_IN_CHARS, i * MSG_SIZE_IN_CHARS
            prevCipherText = paddedString[prevStart : prevEnd]
            yWord = self.Decrypt(curCipherText, KeyText)

            yWordVec = self.__ConvertAlphabetToAsciiCodeList(yWord)
            curCipherTextVec = self.__ConvertAlphabetToAsciiCodeList(prevCipherText)

            plainTextVec = self.VectoredXor(yWordVec, curCipherTextVec)
            plainText = self.__ConvertAsciiListToAlphabet(plainTextVec)
            plainList.append(plainText)

        resString = "".join([c1 for c1 in plainList])
        return resString



if __name__ == '__main__':
    # Default uses FRODO_640 with input as 16 characters
    frodo = FRODO()

    kBin = "10110010" * 16
    kMat = frodo.FrodoEncode(kBin)
    #print ("kMat: {}".format(kMat))

    ckBin =  frodo.FrodoDecode(kMat)
    print ("kBin: {}, ckBin: {}".format(kBin, ckBin))
    
    key = frodo.FrodoPKEKeyGen()
    print ("private key: {}".format(key.sk))
    print ("public key: {}".format(key.pk))

    plainText = "KENNETHISGREATXX"
    cipherText = frodo.Encrypt(plainText, key.pk)

    print ("cipherText: {}".format(cipherText))

    decryptedPlainText = frodo.Decrypt(cipherText, key.sk)
    print ("decryptedPlainText: {}".format(decryptedPlainText))
    

