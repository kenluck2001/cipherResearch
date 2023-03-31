from collections import namedtuple
from enum import Enum
BYTE_SIZE = 8
MSG_SIZE = 128
MSG_SIZE_IN_CHARS = 16

class Version(Enum):
    V128 = "V128"
    V192 = "V192"
    V256 = "V256"

class Mode(Enum):
    ECB = "ECB"
    CBC = "CBC"

class AES:
    """
        ADVANCED ENCRYPTION STANDARD (AES) on ECB mode
        Only 128 bit is supported at the moment
        Reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
    """
    def __init__(self, version = Version.V128, mode = Mode.ECB):
        self.version = version
        self.mode = mode
        Param = namedtuple('Param', ['numOfKeysBits','lenOfKeyAsWords', 'numOfRounds', 'numOfBlocks'])
        if self.version is not Version.V128:
            raise NotImplementedError("{} is not yet supported".format(version.name))
     
        # Adding settings
        paramPer128Bits = Param(128, 4, 10, 4)
        paramPer192Bits = Param(192, 6, 12, 4)
        paramPer256Bits = Param(256, 8, 14, 4)

        self.ParamDict = {
            Version.V128: paramPer128Bits, 
            Version.V192: paramPer192Bits,
            Version.V192: paramPer256Bits,
        }

    def ConvertAlphabetsToBinary (self, s1):
        '''
            Convert alphabet to binary
        '''
        #s1str = "".join([chr(ord(c1)) for c1 in s1])
        #s1str = codecs.encode(s1str, "hex")
        #s1str = bin(int(s1str, 16))[2:]

        asiiLst = [ord(c1) for c1 in s1]
        binString = self.ConvertASCIICodelistToBinary(asiiLst)
        return binString

    def __ConvertBinaryToASCIICode (self, st):
        '''
            Convert binary to ascii code
        '''
        lenOfBinString = len(st) 
        quantizedLenOfBinString = ((lenOfBinString // BYTE_SIZE)+1) * BYTE_SIZE
        numOfBits = quantizedLenOfBinString if (lenOfBinString % BYTE_SIZE) > 0 else lenOfBinString
        quantizedBinString = st.zfill(numOfBits)
        res = []
        for i in range (numOfBits // BYTE_SIZE):
            start, end = i * BYTE_SIZE, (i + 1) * BYTE_SIZE
            curString = quantizedBinString[start : end]
            asciiValue = int(curString, 2)
            res.append(asciiValue)
        return res

    def __ConvertAsciiListToAlphabet (self, res):
        '''
            Convert list of ascii code to alphabet
        '''
        resString = "".join([chr(c1) for c1 in res])
        return resString


    def __ConvertAlphabetToAsciiCodeList (self, res):
        '''
            Convert list of ascii code to alphabet
        '''
        resList = [ord(c1) for c1 in res]
        return resList

    def ConvertASCIICodelistToBinary(self, res, SET_BYTE_SIZE=BYTE_SIZE):
        resString = "".join([bin(c1)[2:].zfill(SET_BYTE_SIZE) for c1 in res])
        return resString

    def ConvertBinaryToAlphabet (self, st):
        '''
            Convert binary to alphabet
        '''
        res = self.__ConvertBinaryToASCIICode(st)
        resString = "".join([chr(c1) for c1 in res])
        return resString

    def LeftCircularShift (self, string, n):
        '''
            Perform left circular shift
        '''
        return string[n:] + string[:n]

    def RightCircularShift (self, string, n):
        '''
            Perform right circular shift
        '''
        return string[-n:] + string[:-n]

    def ForwardSBox (self, b):
        '''
            Affline representation of S-Box
        '''
        scale = 16 ## equals to hexadecimal
        b = b.zfill(BYTE_SIZE)
        s = int(b, 2) ^ int(self.LeftCircularShift(b, 1), 2) ^ int(self.LeftCircularShift(b, 2), 2) ^ int(self.LeftCircularShift(b, 3), 2) ^ int(self.LeftCircularShift(b, 4), 2) ^ int("0x63", 16)
        return s

    def InvSBox (self, s):
        '''
            Affline inverse representation of S-Box
        '''
        s = s.zfill(BYTE_SIZE)
        b = int(self.LeftCircularShift(s, 1), 2) ^ int(self.LeftCircularShift(s, 3), 2) ^ int(self.LeftCircularShift(s, 6), 2) ^ int("0x5", 16)
        return b

    def GenerateBlockMatrixFromText (self, text, INPUT_SIZE = MSG_SIZE):
        '''
            Accept ciphertext or cleartext as input
        '''
        settings = self.ParamDict[self.version]
        # size of keys
        KEY_SIZE = INPUT_SIZE   # N_k
        NUM_OF_BLOCK = settings.numOfBlocks # N_b
        txtBinary = self.ConvertAlphabetsToBinary(text)
        txtBinary = txtBinary.zfill(KEY_SIZE)
        print ("txtBinary: {}".format(txtBinary))
        mat = [[0]* NUM_OF_BLOCK for _ in range (4)]
        for objInd, ind in enumerate(range(0, KEY_SIZE, BYTE_SIZE)):
            start, end = ind , (ind + BYTE_SIZE)
            cRow, cCol = (objInd % 4), (objInd // 4)
            asciiValue = int(txtBinary[start: end], 2)
            mat[cRow][cCol] = asciiValue
        return mat

    def GenerateTextFromBlockMatrix (self, mat, INPUT_SIZE = MSG_SIZE):
        '''
            Accept 2D matrix and ciphertext or cleartext as output
        '''
        settings = self.ParamDict[self.version]
        # size of keys
        KEY_SIZE = INPUT_SIZE   # N_k
        NUM_OF_BLOCK = settings.numOfBlocks # N_b
        resList = []  
        for objInd, _ in enumerate(range(0, KEY_SIZE, BYTE_SIZE)):
            cRow, cCol = (objInd % 4), (objInd // 4)
            resList.append(mat[cRow][cCol])
        resString = "".join([chr(c1) for c1 in resList])
        return resString

    def GMul(self, x, y):
        '''
            Galois Field (256) Multiplication of two Bytes
            https://stackoverflow.com/questions/70261458/how-to-perform-addition-and-multiplication-in-f-28
        '''
        p = 0b100011011             # mpy modulo x^8+x^4+x^3+x+1
        m = 0                       # m will be product
        for _ in range(BYTE_SIZE):
            m = m << 1
            if m & 0b100000000:
                m = m ^ p
            if y & 0b010000000:
                m = m ^ x
            y = y << 1
        return m

    def SubWord (self, word):
        '''
            Apply subword transformation
        '''
        wordVec= word[:] # 32 bit word of distinct 8 bits each
        return self.LeftCircularShift (wordVec, 1)

    def RotWord (self, word):
        '''
            Apply word transformation (bin(60)[2:])
        '''
        wordVec= [self.ForwardSBox(bin(x)[2:]) for x in word[:]] # 32 bit word of distinct 8 bits each
        return wordVec

    def AddRoundKey (self, mat, wlist, currentRound, numOfBlocks):
        '''
            Apply Key expansion transformation
        '''
        numOfCols = len(mat[0])
        for i in range(numOfCols):
            stateVec = [mat[0][i], mat[1][i], mat[2][i], mat[3][i]]
            wVec = wlist [(currentRound * numOfBlocks) + i]
            colVec = self.VectoredXor(stateVec, wVec)
            mat[0][i] = colVec[0]
            mat[1][i] = colVec[1]
            mat[2][i] = colVec[2]
            mat[3][i] = colVec[3]

    def VectoredXor(self, vec1, vec2):
        return [(x ^ y) for x,y in zip(vec1, vec2)]

    def ObtainRoundConstant(self, numOfRounds):
        rclist = [[1, 0, 0, 0]]
        i = 1
        while (i < (numOfRounds+1)):
            if rclist[i - 1][0] < 0x80:
                rclist.append([2*rclist[i - 1][0], 0, 0, 0])
            else:
                cVal = (2*rclist[i - 1][0]) ^ 0x11b
                rclist.append([cVal, 0, 0, 0])
            i = i + 1
        return rclist

    def KeyExpansion(self, key2DMat, lenOfKeyAsWords, numOfRounds, numOfBlocks):
        '''
            Expand the key
        ''' 
        rConList = self.ObtainRoundConstant(numOfRounds)
        temp = None
        wlist = [[0]*4 for _ in range(numOfBlocks * (numOfRounds+1))] #        Accept key as 2D matrix (column by column)
        i = 0
        while (i < lenOfKeyAsWords):
            wlist[i] = [key2DMat[0][i], key2DMat[1][i], key2DMat[2][i], key2DMat[3][i]]
            i = i + 1
        i = lenOfKeyAsWords
        while (i < (numOfBlocks * (numOfRounds+1))):
            temp = wlist[i-1]
            if (i % lenOfKeyAsWords) == 0:
                temp = self.VectoredXor(self.SubWord(self.RotWord(temp)), rConList[i // lenOfKeyAsWords])
            elif (lenOfKeyAsWords > 6) and (i % lenOfKeyAsWords) == 4:
                temp = self.SubWord(temp)
            wlist[i] = self.VectoredXor(wlist[i - lenOfKeyAsWords], temp)            
            i = i + 1
        return wlist

    def SubBytes (self, mat):
        '''
            Apply subBytes transformation
        '''
        numOfRows = len(mat)
        numOfCols = len(mat[0])
        for rowInd in range(numOfRows):
            for colInd in range(numOfCols):
                curValue = bin(mat[rowInd][colInd])[2:]
                mat[rowInd][colInd] = self.ForwardSBox(curValue)

    def ShiftRows (self, mat):
        '''
            Apply shift row transformation
        '''
        numOfRows = len(mat)
        for rowInd in range(numOfRows):
            mat[rowInd] = self.LeftCircularShift (mat[rowInd], rowInd)

    def MixColumns (self, mat):
        '''
            Apply mix column transformation
        '''
        numOfCols = len(mat[0])
        for colInd in range(numOfCols):
            copyColumn = [mat[0][colInd], mat[1][colInd], mat[2][colInd], mat[3][colInd]]
            mat[0][colInd] = self.GMul(0x2, copyColumn[0]) ^ self.GMul(0x3, copyColumn[1]) ^ copyColumn[2] ^ copyColumn[3]
            mat[1][colInd] = copyColumn[0] ^ self.GMul(0x2, copyColumn[1]) ^ self.GMul(0x3, copyColumn[2]) ^ copyColumn[3] 
            mat[2][colInd] = copyColumn[0] ^ copyColumn[1] ^ self.GMul(0x2, copyColumn[2]) ^ self.GMul(0x3, copyColumn[3]) 
            mat[3][colInd] = self.GMul(0x3, copyColumn[0]) ^ copyColumn[1] ^ copyColumn[2] ^ self.GMul(0x2, copyColumn[3])

    def InvSubBytes (self, mat):
        '''
            Apply inverse sub Bytes transformation
        '''
        numOfRows = len(mat)
        numOfCols = len(mat[0])
        for rowInd in range(numOfRows):
            for colInd in range(numOfCols):
                curValue = bin(mat[rowInd][colInd])[2:]
                mat[rowInd][colInd] = self.InvSBox(curValue)

    def InvShiftRows (self, mat):
        '''
            Apply inverse shift row transformation
        '''
        numOfRows = len(mat)
        for rowInd in range(numOfRows):
            mat[rowInd] = self.RightCircularShift (mat[rowInd], rowInd)

    def InvMixColumns (self,mat):
        '''
            Apply inverse mix column transformation
        '''
        numOfCols = len(mat[0])
        for colInd in range(numOfCols):
            copyColumn = [mat[0][colInd], mat[1][colInd], mat[2][colInd], mat[3][colInd]]
            mat[0][colInd] = self.GMul(0x0e, copyColumn[0]) ^ self.GMul(0x0b, copyColumn[1]) ^ self.GMul(0x0d, copyColumn[2]) ^ self.GMul(0x09, copyColumn[3])
            mat[1][colInd] = self.GMul(0x09, copyColumn[0]) ^ self.GMul(0x0e, copyColumn[1]) ^ self.GMul(0x0b, copyColumn[2]) ^ self.GMul(0x0d, copyColumn[3]) 
            mat[2][colInd] = self.GMul(0x0d, copyColumn[0]) ^ self.GMul(0x09, copyColumn[1]) ^ self.GMul(0x0e, copyColumn[2]) ^ self.GMul(0x0b, copyColumn[3]) 
            mat[3][colInd] = self.GMul(0x0b, copyColumn[0]) ^ self.GMul(0x0d, copyColumn[1]) ^ self.GMul(0x09, copyColumn[2]) ^ self.GMul(0x0e, copyColumn[3])

    def Encrypt(self, plainText, KeyText):
        settings = self.ParamDict[self.version]
        numOfKeysBits = settings.numOfKeysBits 
        lenOfKeyAsWords = settings.lenOfKeyAsWords
        numOfRounds = settings.numOfRounds
        numOfBlocks = settings.numOfBlocks
        mat = self.GenerateBlockMatrixFromText (plainText)
        kmat = self.GenerateBlockMatrixFromText (KeyText)
        wlist = self.KeyExpansion(kmat, lenOfKeyAsWords, numOfRounds, numOfBlocks)
        self.AddRoundKey(mat, wlist, 0, numOfBlocks)
        for cRound in range(1, numOfRounds):
            self.SubBytes(mat)
            self.ShiftRows(mat)
            self.MixColumns(mat)
            self.AddRoundKey(mat, wlist, cRound, numOfBlocks)

        self.SubBytes(mat)
        self.ShiftRows(mat)
        self.AddRoundKey(mat, wlist, numOfRounds, numOfBlocks)

        cipherText = self.GenerateTextFromBlockMatrix (mat)
        return cipherText

    def Decrypt(self, cipherText, KeyText):
        settings = self.ParamDict[self.version]
        numOfKeysBits = settings.numOfKeysBits 
        lenOfKeyAsWords = settings.lenOfKeyAsWords
        numOfRounds = settings.numOfRounds
        numOfBlocks = settings.numOfBlocks
        mat = self.GenerateBlockMatrixFromText (cipherText)
        kmat = self.GenerateBlockMatrixFromText (KeyText)
        wlist = self.KeyExpansion(kmat, lenOfKeyAsWords, numOfRounds, numOfBlocks)
        self.AddRoundKey(mat, wlist, numOfRounds, numOfBlocks)
        for cRound in range(numOfRounds-1, 0, -1):
            self.InvShiftRows(mat)
            self.InvSubBytes(mat)
            self.AddRoundKey(mat, wlist, cRound, numOfBlocks)
            self.InvMixColumns(mat)

        self.InvShiftRows(mat)
        self.InvSubBytes(mat)
        self.AddRoundKey(mat, wlist, 0, numOfBlocks)

        plainText = self.GenerateTextFromBlockMatrix (mat)
        return plainText

    def Cipher(self, plainText, KeyText, initVectorString=None):
        '''
            Encryption on group of blocks
        '''
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
    plainText = "KENNETHGREATMANX"
    KeyText =   "CALLMEATNOONXXXX"
    aes = AES()
    cipherText = aes.Encrypt(plainText, KeyText)
    print ("cipherText: {}".format(cipherText))
    expectedPlainText = aes.Decrypt(cipherText, KeyText)
    print ("plainText: {}".format(expectedPlainText))

    assert plainText == expectedPlainText, "DECRYPTION COULD NOT RETURN ORIGINAL PLAINTEXT THAT WAS ENCRYPTED" 

    # aes = AES(Version.V192)
    # ECB mode (default)
    plainText = "KENNETHGREATMANPLEASECALLHIMINMYHOUSEKENNETHGREATMANPLEASECALLHIMINMYHOUSE"
    KeyText =   "CALLMEATNOONXXXX"
    initVectorString =   "SENDMEHOMENOWXXX"
    aes = AES()
    cipherText = aes.Cipher(plainText, KeyText)
    print ("cipherText: {}".format(cipherText))
    expectedPlainText = aes.InvCipher(cipherText, KeyText)
    print ("plainText: {}".format(expectedPlainText))

    # CBC mode
    plainText = "KENNETHGREATMANPLEASECALLHIMINMYHOUSEKENNETHGREATMANPLEASECALLHIMINMYHOUSE"
    KeyText =   "CALLMEATNOONXXXX"
    initVectorString =   "SENDMEHOMENOWXXX"
    aes = AES(mode = Mode.CBC)
    cipherText = aes.Cipher(plainText, KeyText, initVectorString=initVectorString)
    print ("cipherText: {}".format(cipherText))
    expectedPlainText = aes.InvCipher(cipherText, KeyText, initVectorString=initVectorString)
    print ("plainText: {}".format(expectedPlainText))

    prependString = 'comment1"="cooking%20MCs";"userdata"="'
    appendString = '";"comment2"="%20like%20a%20pound%20of%20bacon'
    plainText = "{}kenneth{}".format(prependString, appendString)
    KeyText =   "CALLMEATNOONXXXX"
    initVectorString =   "SENDMEHOMENOWXXX"
    aes = AES(mode = Mode.CBC)
    cipherText = aes.Cipher(plainText, KeyText, initVectorString=initVectorString)
    print ("cipherText: {}".format(cipherText))
    expectedPlainText = aes.InvCipher(cipherText, KeyText, initVectorString=initVectorString)
    print ("plainText: {}".format(expectedPlainText))


