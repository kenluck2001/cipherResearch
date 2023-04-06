from collections import namedtuple
from enum import Enum
#import codecs

BYTE_SIZE = 8
MSG_SIZE = 64
MSG_SIZE_IN_CHARS = 8
NUM_OF_ROUNDS = 16


class Mode(Enum):
    ECB = "ECB"
    CBC = "CBC"


class DES:
    """
        DATA ENCRYPTION STANDARD (DES)
        Reference: https://web.archive.org/web/20110427082733/http://www.itl.nist.gov/fipspubs/fip46-2.htm
    """

    def __init__(self, mode=Mode.ECB):
        self.mode = mode

    def ConvertAlphabetsToBinary(self, s1):
        '''
            Convert alphabet to binary
        '''
        #s1str = "".join([chr(ord(c1)) for c1 in s1])
        #s1str = codecs.encode(s1str, "hex")
        #s1str = bin(int(s1str, 16))[2:]

        asiiLst = [ord(c1) for c1 in s1]
        binString = self.ConvertASCIICodelistToBinary(asiiLst)
        return binString

    def __ConvertBinaryToASCIICode(self, st, SET_BYTE_SIZE=BYTE_SIZE):
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

    def __ConvertAsciiListToAlphabet(self, res):
        '''
            Convert list of ascii code to alphabet
        '''
        resString = "".join([chr(c1) for c1 in res])
        return resString

    def __ConvertAlphabetToAsciiCodeList(self, res):
        '''
            Convert list of ascii code to alphabet
        '''
        resList = [ord(c1) for c1 in res]
        return resList

    def ConvertBinaryToAlphabet(self, st):
        '''
            Convert binary to alphabet
        '''
        res = self.__ConvertBinaryToASCIICode(st)
        resString = "".join([chr(c1) for c1 in res])
        return resString

    def LeftCircularShift(self, string, n):
        '''
            Perform left circular shift
        '''
        return string[n:] + string[:n]

    def RightCircularShift(self, string, n):
        '''
            Perform right circular shift
        '''
        return string[-n:] + string[:-n]

    def ForwardSBox(self, b):
        '''
            Affline representation of S-Box
        '''
        scale = 16  ## equals to hexadecimal
        b = b.zfill(BYTE_SIZE)
        s = int(b, 2) ^ int(self.LeftCircularShift(b, 1), 2) ^ int(self.LeftCircularShift(b, 2), 2) ^ int(
            self.LeftCircularShift(b, 3), 2) ^ int(self.LeftCircularShift(b, 4), 2) ^ int("0x63", 16)
        return s

    def InvSBox(self, s):
        '''
            Affline inverse representation of S-Box
        '''
        s = s.zfill(BYTE_SIZE)
        b = int(self.LeftCircularShift(s, 1), 2) ^ int(self.LeftCircularShift(s, 3), 2) ^ int(
            self.LeftCircularShift(s, 6), 2) ^ int("0x5", 16)
        return b

    def VectoredXor(self, vec1, vec2):
        return [(x ^ y) for x, y in zip(vec1, vec2)]

    def __Encrypt(self, l0, r0, keylist):
        '''
            l0 is 32 bit (4 bytes), r0 is 32 bit (4 bytes)
            using a list of 4 elements to represent it
            return r16, l16
        '''
        lList = [[0] * 4 for _ in range(NUM_OF_ROUNDS + 1)]
        rList = [[0] * 4 for _ in range(NUM_OF_ROUNDS + 1)]
        lList[0] = l0
        rList[0] = r0
        for ind in range(1, NUM_OF_ROUNDS + 1):
            lList[ind] = rList[ind - 1]
            cipherFuncReturns = self.CipherFunc(rList[ind - 1], keylist[ind])
            rList[ind] = self.VectoredXor(lList[ind - 1], cipherFuncReturns)
        return rList[NUM_OF_ROUNDS], lList[NUM_OF_ROUNDS]

    def __Decrypt(self, r16, l16, keylist):
        '''
            l16 is 32 bit (4 bytes), r16 is 32 bit (4 bytes)
            using a list of 4 elements to represent it
            return l16, r16
        '''
        lList = [[0] * 4 for _ in range(NUM_OF_ROUNDS + 1)]
        rList = [[0] * 4 for _ in range(NUM_OF_ROUNDS + 1)]
        lList[NUM_OF_ROUNDS] = l16
        rList[NUM_OF_ROUNDS] = r16
        for ind in range(NUM_OF_ROUNDS, 0, -1):
            rList[ind - 1] = lList[ind]
            cipherFuncReturns = self.CipherFunc(lList[ind], keylist[ind])
            lList[ind - 1] = self.VectoredXor(rList[ind], cipherFuncReturns)
        return lList[0], rList[0]

    def CipherFunc(self, rValueVec, keyVec):
        '''
        returns 32 bits
        '''
        erVec = self.ER(rValueVec)  #48 bits
        res = self.VectoredXor(erVec, keyVec)
        return res

    def Encrypt(self, plainText, KeyText):
        '''
            plainText: 64 bits (8 alphabets characters)
            KeyText: 64 bits (8 alphabets characters)
        '''
        plainTextVec = self.GenerateVecFromText(plainText)
        KeyTextVec = self.GenerateVecFromText(KeyText)
        halfWord = BYTE_SIZE // 2  # 4 bytes
        l0, r0 = plainTextVec[:halfWord], plainTextVec[halfWord:]
        # Create key list
        keylist = self.GenerateExpandedKeyList(KeyTextVec)
        r16, l16 = self.__Encrypt(l0, r0, keylist)
        combineList = r16 + l16
        cipherText = self.__ConvertAsciiListToAlphabet(combineList)
        return cipherText

    def Decrypt(self, cipherText, KeyText):
        '''
            cipherText: 64 bits (8 alphabets characters)
            KeyText: 64 bits (8 alphabets characters)
        '''
        cipherTextVec = self.GenerateVecFromText(cipherText)
        KeyTextVec = self.GenerateVecFromText(KeyText)
        halfWord = BYTE_SIZE // 2  # 4 bytes
        r16, l16 = cipherTextVec[:halfWord], cipherTextVec[halfWord:]
        # Create key list
        keylist = self.GenerateExpandedKeyList(KeyTextVec)
        l0, r0 = self.__Decrypt(r16, l16, keylist)
        combineList = l0 + r0
        plainText = self.__ConvertAsciiListToAlphabet(combineList)
        return plainText

    def GenerateVecFromText(self, text):
        binString = self.ConvertAlphabetsToBinary(text)
        textVec = self.__ConvertBinaryToASCIICode(binString)
        return textVec

    def ConvertASCIICodelistToBinary(self, res, SET_BYTE_SIZE=BYTE_SIZE):
        resString = "".join([bin(c1)[2:].zfill(SET_BYTE_SIZE) for c1 in res])
        return resString

    def ER(self, rValueLst):
        '''
            rValue: 32 bit of 4 element list
            output 48 bits
        '''
        permOrderList = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
                         19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
        permutatedBinary = self.permWithOrderToBinary(permOrderList, rValueLst)
        resList = self.__ConvertBinaryToASCIICode(permutatedBinary)
        return resList

    def __getSBox(self, resBinary):
        numOfBits = len(resBinary)
        res = []
        CUSTOM_BYTE_SIZE = 6
        for i in range(numOfBits // CUSTOM_BYTE_SIZE):
            start, end = i * CUSTOM_BYTE_SIZE, (i + 1) * CUSTOM_BYTE_SIZE
            curString = resBinary[start: end]
            row, col = int(curString[: 2], 2), int(curString[2:], 2)
            res.append((row, col))

        listS1 = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                  [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                  [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                  [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
                  ]

        row, col = res[0]
        S1 = listS1[row][col]
        S1 = format(S1, '04b')

        listS2 = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                  [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                  [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                  [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
                  ]
        row, col = res[1]
        S2 = listS2[row][col]
        S2 = format(S2, '04b')

        listS3 = [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                  [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                  [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                  [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
                  ]

        row, col = res[2]
        S3 = listS3[row][col]
        S3 = format(S3, '04b')

        listS4 = [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                  [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                  [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                  [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
                  ]

        row, col = res[3]
        S4 = listS4[row][col]
        S4 = format(S4, '04b')

        listS5 = [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                  [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                  [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                  [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
                  ]

        row, col = res[4]
        S5 = listS5[row][col]
        S5 = format(S5, '04b')

        listS6 = [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                  [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                  [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                  [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
                  ]

        row, col = res[5]
        S6 = listS6[row][col]
        S6 = format(S6, '04b')

        listS7 = [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                  [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                  [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                  [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
                  ]

        row, col = res[6]
        S7 = listS7[row][col]
        S7 = format(S7, '04b')

        listS8 = [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                  [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                  [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                  [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
                  ]

        row, col = res[7]
        S8 = listS8[row][col]
        S8 = format(S8, '04b')

        output = '{0}{1}{2}{3}{4}{5}{6}{7}'.format(S1, S2, S3, S4, S5, S6, S7, S8)
        return output

    def getSBox(self, res):
        '''
            convert 48 bits (6 element list) to 32 bits
        '''
        resBinary = self.ConvertASCIICodelistToBinary(res)
        sBoxTxt = self.__getSBox(resBinary)
        resList = self.__ConvertBinaryToASCIICode(sBoxTxt)
        return resList

    def permSBox(self, sValueLst):
        permOrderList = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
                         13, 30, 6, 22, 11, 4, 25]
        permutatedBinary = self.permWithOrderToBinary(permOrderList, sValueLst)
        resList = self.__ConvertBinaryToASCIICode(permutatedBinary)
        return resList

    ## key schedule
    def permWithOrderToBinary(self, permOrderList, valueLst):
        resList = []
        valueBinary = self.ConvertASCIICodelistToBinary(valueLst)
        for ind in permOrderList:
            resList.append(valueBinary[ind - 1])
        permutatedBinary = ''.join(resList)
        return permutatedBinary

    def permChoice1(self, valueLst):
        '''
            input: 64 bits
	        output is 56-bit permutation
            valuelist is 8 element list
        '''
        permOrderList = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
                         52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
                         21, 13, 5, 28, 20, 12, 4]
        permutatedBinary = self.permWithOrderToBinary(permOrderList, valueLst)
        resList = self.__ConvertBinaryToASCIICode(permutatedBinary)
        return resList

    def permChoice2(self, valueLst):
        '''
            input is 56 bit
            output is 48-bit
            valuelist is 8 element list
        '''
        permOrderList = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
                         31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
        permutatedBinary = self.permWithOrderToBinary(permOrderList, valueLst)
        resList = self.__ConvertBinaryToASCIICode(permutatedBinary)
        return resList

    def ObtainKeyListParameters(self, valueLst):
        '''
            valueList is a vectored keyText
            key schedule logic
        '''
        # Replace this call with segmenting binary strings by 4 bits
        # TODO methods to use ConvertASCIICodelistToBinary, __ConvertBinaryToASCIICode and permWithOrderToBinary
        permutatedKey = self.permChoice1(valueLst)
        permutatedKeyBinary = self.ConvertASCIICodelistToBinary(permutatedKey)
        permutatedKeyVec = self.__ConvertBinaryToASCIICode(permutatedKeyBinary, SET_BYTE_SIZE=BYTE_SIZE // 2)
        # segment by 4 bits inside of 8 bits to prevent fractional bytes
        c, d = permutatedKeyVec[: 7], permutatedKeyVec[7:]  # c0, do are 28 bit each
        keyList = []
        keyList.append((c, d))
        for num in range(1, (NUM_OF_ROUNDS + 1)):
            if (num == 1) or (num == 2) or (num == 9) or (num == 16):
                c = self.LeftCircularShift(c, 1)
                d = self.LeftCircularShift(d, 1)
            else:
                c = self.LeftCircularShift(c, 2)
                d = self.LeftCircularShift(d, 2)
            keyList.append((c, d))
        return keyList

    def GenerateExpandedKeyList(self, valueLst):
        '''
            Generate a list of keys
        '''
        keyList = []
        keyParamsLst = self.ObtainKeyListParameters(valueLst)
        for c,d in keyParamsLst:
            roundCipherLst = c + d # merge list
            permRoundCipherBinary = self.ConvertASCIICodelistToBinary(roundCipherLst, SET_BYTE_SIZE=BYTE_SIZE // 2)
            permRoundCipherKeyVec = self.__ConvertBinaryToASCIICode(permRoundCipherBinary)
            keyList.append ( self.permChoice2(permRoundCipherKeyVec) )
        return keyList


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

    plainText = "KENNETHX"
    KeyText =   "CALLMEAT"
    des = DES()
    cipherText = des.Encrypt(plainText, KeyText)
    print ("cipherText: {}".format(cipherText))
    expectedPlainText = des.Decrypt(cipherText, KeyText)
    print ("plainText: {}".format(expectedPlainText))

    assert plainText == expectedPlainText, "DECRYPTION COULD NOT RETURN ORIGINAL PLAINTEXT THAT WAS ENCRYPTED" 

    # ECB mode
    plainText = "KENNETHGREATMANPLEASECALLHIMINMYHOUSEKENNETHGREATMANPLEASECALLHIMINMYHOUSE"
    KeyText =   "CALLMEAT"
    initVectorString =   "SENDHOME"
    des = DES(mode = Mode.ECB)
    cipherText = des.Cipher(plainText, KeyText)
    print ("cipherText: {}".format(cipherText))
    expectedPlainText = des.InvCipher(cipherText, KeyText)
    print ("plainText: {}".format(expectedPlainText))

    des = DES( mode = Mode.ECB)
    cipherText = des.Cipher(plainText, KeyText, initVectorString=initVectorString)
    print ("cipherText: {}".format(cipherText))
    expectedPlainText = des.InvCipher(cipherText, KeyText, initVectorString=initVectorString)
    print ("plainText: {}".format(expectedPlainText))

    des = DES(mode = Mode.CBC)
    cipherText = des.Cipher(plainText, KeyText, initVectorString=initVectorString)
    print ("cipherText: {}".format(cipherText))
    expectedPlainText = des.InvCipher(cipherText, KeyText, initVectorString=initVectorString)
    print ("plainText: {}".format(expectedPlainText))


