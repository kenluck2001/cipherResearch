from collections import namedtuple
from enum import Enum

BYTE_SIZE = 8
WORD_SIZE = 64
KEY_NONCE_SIZE = 128

class PermuteMode(Enum):
    A = "A"
    B = "B"

class Version(Enum):
    ASCON128 = "Ascon-128"
    ASCON128a = "Ascon-128a"

class Phase(Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"

class ASCON:
    """
        Ascon v1.2
        Reference: http://ascon.iaik.tugraz.at
    """
    def __init__(self, version = Version.ASCON128):
        self.PERMUTATION_CONSTANT = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
        self.version = version
        Param = namedtuple('Param', ['keyLength', 'a', 'b', 'r', 'c'])

        # Adding settings
        paramPerAscon128  = Param(128, 12, 6,  64, 256)
        paramPerAscon128a = Param(128, 12, 8, 128, 192)

        self.ParamDict = {
            Version.ASCON128: paramPerAscon128, 
            Version.ASCON128a: paramPerAscon128a,
        }
        self.stateVec = None # stateVec: 5 elements in list (each element is 64 bits)

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
        return [(x ^ y) for x, y in zip(vec1, vec2)]

    def HadamardProductTripletVec(self, vec1, vec2, vec3):
        return [(x & y & z) for x, y, z in zip(vec1, vec2, vec3)]

    def getAlphabetFromBinaryText (self, textBin):
        alphabetString = self.ConvertBinaryToAlphabet(textBin)
        return alphabetString

    ########
    def __initVecBinary(self):
        '''
            Create the initialization vector
            output: 64 bits
        '''
        settings = self.ParamDict[self.version]
        keyLength = settings.keyLength 
        a = settings.a 
        b = settings.b
        r = settings.r 
        keyLengthBin = bin(a)[2:].zfill(BYTE_SIZE)
        aBin = bin(a)[2:].zfill(BYTE_SIZE)
        bBin = bin(b)[2:].zfill(BYTE_SIZE)
        rBin = bin(r)[2:].zfill(BYTE_SIZE)
        paddingLen = 288 - (2 * keyLength)
        paddingText = '0'* paddingLen
        output = '{0}{1}{2}{3}{4}'.format(keyLengthBin, rBin, aBin, bBin, paddingText)

        return output

    def CreateState(self, keyText, nonceText):
        '''
            input: 
                keyText: 128 bits (16 alphabets characters)
                nonceText: 128 bits (16 alphabets characters)
            output: 320 bits string
        '''
        ivBin = self.__initVecBinary()
        keyTextBin = self.ConvertAlphabetsToBinary(keyText)
        nonceTextBin = self.ConvertAlphabetsToBinary(nonceText)
        stateBin = '{0}{1}{2}'.format(ivBin, keyTextBin.zfill(KEY_NONCE_SIZE), nonceTextBin.zfill(KEY_NONCE_SIZE))

        return stateBin

    def InitState(self, keyText, nonceText):
        '''
            input: 
                keyText: 128 bits (16 alphabets characters)
                nonceText: 128 bits (16 alphabets characters)
            output: 5 element list where each element is 64 bits
        '''
        settings = self.ParamDict[self.version]
        keyLength = settings.keyLength 
        a = settings.a 
        b = settings.b

        stateBin = self.CreateState(keyText, nonceText)
        stateVec = self.GenerateVecFromBinaryText(stateBin, SET_BYTE_SIZE=WORD_SIZE)

        keyTextBin = self.ConvertAlphabetsToBinary(keyText)
        frontPaddedForKeyBin = "0" * (320 - keyLength)
        paddedKeyBin = '{0}{1}'.format(frontPaddedForKeyBin, keyTextBin.zfill(KEY_NONCE_SIZE))
        paddedKeyVec = self.GenerateVecFromBinaryText(paddedKeyBin, SET_BYTE_SIZE=WORD_SIZE)
        permStateVec = self.Permutate(stateVec, a, b, PermuteMode.A)
        # update state
        self.stateVec = self.VectoredXor(permStateVec, paddedKeyVec)

    def ProcessAssociatedData(self, associatedDataText):
        '''
            Processing associated data layer
            input: 
                associatedDataText: arbitrary length of additional text
        '''
        settings = self.ParamDict[self.version]
        a = settings.a 
        b = settings.b
        r = settings.r
        stateBin = self.ConvertVecToBinary(self.stateVec, SET_BYTE_SIZE=WORD_SIZE)    
        stateRBin, stateCBin = stateBin[ : r], stateBin[ r : ]

        stateRVec = self.GenerateVecFromBinaryText(stateRBin, SET_BYTE_SIZE=r)

        assocDataVec, _ = self.PaddingMessageBlocks(associatedDataText)
        s = len(assocDataVec)
        for ind in range(s):
            aDataVec = [assocDataVec[ind]]
            prefixVec = self.VectoredXor(stateRVec, aDataVec)
            prefixVecBin = self.ConvertVecToBinary(prefixVec, SET_BYTE_SIZE=r)
            stateBin = '{0}{1}'.format(prefixVecBin, stateCBin)
            # update state
            self.stateVec = self.GenerateVecFromBinaryText(stateBin, SET_BYTE_SIZE=WORD_SIZE)
            self.stateVec = self.Permutate(self.stateVec, a, b, PermuteMode.B)

        modifyStateBin = '{0}{1}'.format("0" * 319, "1")
        modifyStateVec = self.GenerateVecFromBinaryText(modifyStateBin, SET_BYTE_SIZE=WORD_SIZE)
        # update state
        self.stateVec = self.VectoredXor(self.stateVec, modifyStateVec)

    def ProcessPlainText(self, plainText):
        '''
            Processing plaintext
            input: 
                plainText: arbitrary length of additional text
            return a list of t-element each a binary string of 128 bits each
        '''
        settings = self.ParamDict[self.version]
        a = settings.a 
        b = settings.b
        r = settings.r
        stateBin = self.ConvertVecToBinary(self.stateVec, SET_BYTE_SIZE=WORD_SIZE)    
        stateRBin, stateCBin = stateBin[ : r], stateBin[ r : ]

        stateRVec = self.GenerateVecFromBinaryText(stateRBin, SET_BYTE_SIZE=r)
        plainTextVec, lengthPlainTxt = self.PaddingMessageBlocks(plainText)

        cipherBlockLst = []
        t = len(plainTextVec)
        for ind in range(t-1):
            plainTxtVec = [plainTextVec[ind]]
            stateRVec = self.VectoredXor(stateRVec, plainTxtVec)
            stateRBin = self.ConvertVecToBinary(stateRVec, SET_BYTE_SIZE=r)    
            cipherBlockLst.append (stateRBin)
            # update state
            self.stateVec = self.Permutate(self.stateVec, a, b, PermuteMode.B)

        plainTxtVec = [plainTextVec[t-1]]
        stateRVec = self.VectoredXor(stateRVec, plainTxtVec)
        stateRBin = self.ConvertVecToBinary(stateRVec, SET_BYTE_SIZE=r)   
        stateBin = '{0}{1}'.format(stateRBin, stateBin[r: ])
        # update state
        self.stateVec = self.GenerateVecFromBinaryText(stateBin, SET_BYTE_SIZE=WORD_SIZE)
     
        # handle last segment
        l = lengthPlainTxt % r
        stateRBin = stateRBin if l == 0 else stateRBin[ : l]
        cipherBlockLst.append (stateRBin)

        cipherText = "".join([self.getAlphabetFromBinaryText (textBin) for textBin in cipherBlockLst])

        return cipherText

    def ProcessCipherText(self, cipherText):
        '''
            Processing cipher text
            input: 
                cipherText: arbitrary length of additional text
            return a list of t-element each a binary string of 128 bits each
        '''
        settings = self.ParamDict[self.version]
        a = settings.a 
        b = settings.b
        r = settings.r
        stateBin = self.ConvertVecToBinary(self.stateVec, SET_BYTE_SIZE=WORD_SIZE)    
        stateRBin, stateCBin = stateBin[ : r], stateBin[ r : ]

        stateRVec = self.GenerateVecFromBinaryText(stateRBin, SET_BYTE_SIZE=r)
        cipherTextVec, lengthCipher = self.PaddingMessageBlocks(cipherText, phase=Phase.DECRYPT)

        plainBlockLst = []
        t = len(cipherTextVec)
        for ind in range(t-1):
            cipherTxtVec = [cipherTextVec[ind]]
            plainTxtVec = self.VectoredXor(stateRVec, cipherTxtVec)
            plainBin = self.ConvertVecToBinary(plainTxtVec, SET_BYTE_SIZE=r)    
            plainBlockLst.append (plainBin)

            cipherBin = self.ConvertVecToBinary(cipherTxtVec, SET_BYTE_SIZE=r)    
            stateBin = '{0}{1}'.format(cipherBin, stateCBin)
            # update state
            self.stateVec = self.GenerateVecFromBinaryText(stateBin, SET_BYTE_SIZE=r)
            self.stateVec = self.Permutate(self.stateVec, a, b, PermuteMode.B)

        # handle last segment
        l = lengthCipher % r
        cipherTxtVec = [cipherTextVec[t-1]]
        cipherBin = self.ConvertVecToBinary(cipherTxtVec, SET_BYTE_SIZE=r)    
        plainBin = self.__getUnEqualLastMessage(r, l, stateRBin, cipherBin)
        plainBlockLst.append (plainBin)

        # update state
        self.stateVec = self.__updateState(r, l, cipherBin)

        plainText = "".join([self.getAlphabetFromBinaryText (textBin) for textBin in plainBlockLst])

        return plainText

    def __getUnEqualLastMessage(self, r, l, stateRBin, cipherTextBin):
        '''
            Handle edge case in last segment
            Xor logic and return binary strings
        '''
        stateRBin = stateRBin if l == 0 else stateRBin[ : l]
        res = int (stateRBin, 2) ^ int (cipherTextBin, 2)
        return bin(res)[2:].zfill(r - l)

    def __updateState(self, r, l, cipherBin):
        '''
            Handle edge case in last segment
            update state
        '''
        stateBin = self.ConvertVecToBinary(self.stateVec, SET_BYTE_SIZE=WORD_SIZE)    
        stateRBin, stateCBin = stateBin[ : r], stateBin[ r : ]

        if l==0:
            stateBin = '{0}{1}'.format(cipherBin, stateCBin)
            stateVec = self.GenerateVecFromBinaryText(stateBin, SET_BYTE_SIZE=WORD_SIZE)

            return stateVec      

        # handle unequal length
        msgPaddedBin = '{0}{1}'.format("1", "0" * (r - l - 1))
        stateCPState = int (stateRBin[(l - r) :], 2) ^ int (msgPaddedBin, 2)
        stateCPBin = bin(stateCPState)[2:].zfill(r - l)

        stateRBin = '{0}{1}'.format(cipherBin, stateCPBin)
        stateBin = '{0}{1}'.format(stateRBin, stateCBin)
        stateVec = self.GenerateVecFromBinaryText(stateBin, SET_BYTE_SIZE=WORD_SIZE)

        return stateVec

    def __getTag(self, keyText):
        '''
            input: 
                keyText: 128 bits (16 alphabets characters)
            output: 2 element list with 64 bits
        '''
        settings = self.ParamDict[self.version]
        keyLength = settings.keyLength 
        a = settings.a 
        b = settings.b
        r = settings.r 
        c = settings.c 

        keyTextBin = self.ConvertAlphabetsToBinary(keyText).zfill(KEY_NONCE_SIZE)
        keyTextBinVec = self.GenerateVecFromBinaryText(keyTextBin, SET_BYTE_SIZE=WORD_SIZE)

        paddedKeyBin = '{0}{1}{2}'.format("0" * r, keyTextBin, "0" * (c - keyLength))
        paddedKeyVec = self.GenerateVecFromBinaryText(paddedKeyBin, SET_BYTE_SIZE=WORD_SIZE)

        stateVec = self.VectoredXor(self.stateVec, paddedKeyVec)
        # update state
        self.stateVec = self.Permutate(stateVec, a, b, PermuteMode.A)
        stateBin = self.ConvertVecToBinary(self.stateVec, SET_BYTE_SIZE=WORD_SIZE)
        stateBinWithkLSB = stateBin[-keyLength : ]
        stateBinWithkLSBVec = self.GenerateVecFromBinaryText(stateBinWithkLSB, SET_BYTE_SIZE=WORD_SIZE)
        tagVec = self.VectoredXor(stateBinWithkLSBVec, keyTextBinVec)

        return tagVec

    def GetTag(self, keyText):
        '''
            Obtain tag
            input: 
                keyText: 128 bits (16 alphabets characters)
            output: 16 alphabets characters
        '''
        tagVec = self.__getTag(keyText)
        tagBin = self.ConvertVecToBinary(tagVec, SET_BYTE_SIZE=WORD_SIZE)
        tagAlphabet = self.ConvertBinaryToAlphabet(tagBin)

        return tagAlphabet

    def VerifyTag(self, keyText, tagText):
        '''
            Verifying tag
            input: 
                keyText: 128 bits (16 alphabets characters)
                tagText: 128 bits (16 alphabets characters)
            output: true or false
        '''
        tagVec = self.__getTag(keyText)
        tagBin = self.ConvertVecToBinary(tagVec, SET_BYTE_SIZE=WORD_SIZE)
        tagAlphabet = self.ConvertBinaryToAlphabet(tagBin)
        print ("tagAlphabet: {}, tagText: {}".format(tagAlphabet, tagText))
        return tagAlphabet == tagText

    def PaddingMessageBlocks(self, text, phase=Phase.ENCRYPT):
        '''
            Pad the message blocks
            input:
                text: string of alphabets of arbitrary length
                phase: enum with value of encrypt, decrypt
            output: r-bit blocks of text in a list and lenght of text
        '''
        settings = self.ParamDict[self.version]
        r = settings.r 
        textVec = self.GenerateVecFromText(text)
        textBin = self.ConvertVecToBinary(textVec)
        length = len(textBin)
        
        if phase is Phase.DECRYPT:        
            textBinVec = self.GenerateVecFromBinaryText(textBin, SET_BYTE_SIZE=r)
            return textBinVec, length

        # Encrypt phase
        suffixPadLen = r - 1 - (length % r)
        textPaddedBin = '{0}{1}{2}'.format(textBin, "1", "0" * suffixPadLen)
        textPaddedBinVec = self.GenerateVecFromBinaryText(textPaddedBin, SET_BYTE_SIZE=r)

        return textPaddedBinVec, length

    def __padUsingPKCV7(self, text, characterCount =16):
        text = text[: characterCount]
        text = "{}{}".format(text, "\x04"*(characterCount - len(text)))
        return text

    def Encrypt(self, plainText, keyText, associatedDataText, nonceText):
        '''
            input: 
                plainText: arbitrary length of additional text
                keyText: 128 bits (16 alphabets characters)
                associatedDataText: arbitrary length of additional text
                nonceText: 128 bits (16 alphabets characters)
            output: return a tuple of cipher text of alphabets, and tag composed of alphabets
        '''
        self.stateVec = None # stateVec: 5 elements in list (each element is 64 bits)
        # pad using PKCV7 to 128 bits
        keyText = self.__padUsingPKCV7(keyText)
        nonceText = self.__padUsingPKCV7(nonceText)

        self.InitState(keyText, nonceText)
        self.ProcessAssociatedData(associatedDataText)
        cipherText = self.ProcessPlainText(plainText)
        tagText = self.GetTag(keyText)
        # pad using PKCV7
        tagText = self.__padUsingPKCV7(tagText)

        # reset the state
        self.stateVec = None
        return cipherText, tagText

    def Decrypt(self, cipherText, keyText, associatedDataText, nonceText, tagText):
        '''
            input: 
                cipherText: arbitrary length of additional text
                keyText: 128 bits (16 alphabets characters)
                associatedDataText: arbitrary length of additional text
                nonceText: 128 bits (16 alphabets characters)
                tagText: 128 bits (16 alphabets characters)
            output: return a tuple of plaintext of alphabets, and tag composed of alphabets
        '''
        self.stateVec = None # stateVec: 5 elements in list (each element is 64 bits)
        # pad using PKCV7
        keyText = self.__padUsingPKCV7(keyText)
        nonceText = self.__padUsingPKCV7(nonceText)
        tagText = self.__padUsingPKCV7(tagText)

        self.InitState(keyText, nonceText)
        self.ProcessAssociatedData(associatedDataText)
        plainText = self.ProcessCipherText(cipherText)
        tagStatus = self.VerifyTag(keyText, tagText)

        if not tagStatus:
            #raise Exception("MAC (signature matching failed)") 
            print ("There is forgery in the message, signature mismatch")
            return None
        return plainText

    def GenerateVecFromText(self, text):
        '''
            Convert alphabet text to vector
        '''
        binString = self.ConvertAlphabetsToBinary(text)
        textVec = self.__ConvertBinaryToVec(binString)
        return textVec

    def GenerateVecFromBinaryText(self, text, SET_BYTE_SIZE=BYTE_SIZE):
        '''
            Convert binary string to vector
        '''
        textVec = self.__ConvertBinaryToVec(text, SET_BYTE_SIZE=SET_BYTE_SIZE)
        return textVec

    def ConvertVecToBinary(self, res, SET_BYTE_SIZE=BYTE_SIZE):
        resString = "".join([bin(c1)[2:].zfill(SET_BYTE_SIZE) for c1 in res])
        return resString

    def __getSBox(self, resBinary):
        """
            input:
                resBinary: 320 bits
            output: binary strings
        """
        numOfBits = len(resBinary)
        res = []
        CUSTOM_BYTE_SIZE = 5
        for i in range(numOfBits // CUSTOM_BYTE_SIZE):
            start, end = i * CUSTOM_BYTE_SIZE, (i + 1) * CUSTOM_BYTE_SIZE
            curString = resBinary[start: end]
            curVal = int(curString, 2)
            res.append(curVal)

        sBoxList = [4, 11, 31, 20, 26, 21, 9, 2, 27, 5, 8, 18, 29, 3, 6, 28, 30, 19, 7, 14, 0, 13, 17, 24, 16, 12, 1, 25, 22, 10, 15, 23]
        resSbox = []
        # apply SBOX transformartion
        for val in res:
            resSbox.append (sBoxList[val])

        output = self.ConvertVecToBinary(resSbox, SET_BYTE_SIZE=CUSTOM_BYTE_SIZE)
        return output

    def GetSubLayer(self, res):
        '''
            Substitution layer
            input: 
                res: 5 elements in list (each element is 64 bits)
            output: 5 elements in list (each element is 64 bits)
        '''
        resBinary = self.ConvertVecToBinary(res, SET_BYTE_SIZE=WORD_SIZE)
        sBoxTxt = self.__getSBox(resBinary)
        resList = self.__ConvertBinaryToVec(sBoxTxt, SET_BYTE_SIZE=WORD_SIZE)

        return resList

    def GetDiffLayer(self, res):
        '''
            Linear diffusion layer
            input: 
                res: 5 elements in list (each element is 64 bits)
            output: 5 element list where each element is 64 bits
        '''
        N = len(res)
        outputList = []
        curList = [0 for _ in range(N)]
        for val in res:
            outputList.append (bin(val)[2:].zfill(WORD_SIZE))

        curList[0] = res[0] ^ int(self.RightCircularShift(outputList[0], 19), 2) ^ int(self.RightCircularShift(outputList[0], 28), 2)
        curList[1] = res[1] ^ int(self.RightCircularShift(outputList[1], 61), 2) ^ int(self.RightCircularShift(outputList[1], 39), 2)
        curList[2] = res[2] ^ int(self.RightCircularShift(outputList[2], 1), 2)  ^ int(self.RightCircularShift(outputList[2], 6), 2)
        curList[3] = res[3] ^ int(self.RightCircularShift(outputList[3], 10), 2) ^ int(self.RightCircularShift(outputList[3], 17), 2)
        curList[4] = res[4] ^ int(self.RightCircularShift(outputList[4], 7), 2)  ^ int(self.RightCircularShift(outputList[4], 41), 2)
        
        return curList

    def ObtainConstantLayer(self, res, a, b, rnd, permMode=PermuteMode.A):
        '''
            Addition of Constants
            input: 
                res: 5 elements in list (each element is 64 bits)
                a, b: integers
                rnd: round number
            output: 5 element list where each element is 64 bits
        '''
        ind = 2
        outputList = [x for x in res]

        if permMode is PermuteMode.A:
            rA = rnd
            outputList[ind] = outputList[ind] ^ self.PERMUTATION_CONSTANT[rA]
        else:
            rB = rnd + a - b
            outputList[ind] = outputList[ind] ^ self.PERMUTATION_CONSTANT[rB]

        return outputList

    def _permutate(self, res, a, b, permMode):
        '''
            SPN-based round transformation
            input: 
                res: 5 elements in list (each element is 64 bits)
                a, b: integers
            output: 5 element list where each element is 64 bits
        '''
        NUMOFROUNDS = a if permMode is PermuteMode.A else b
        for rnd in range(NUMOFROUNDS):
            plVec = self.GetDiffLayer(res)
            psVec = self.GetSubLayer(res)
            pcVec = self.ObtainConstantLayer(res, a, b, rnd, permMode)
            res = self.HadamardProductTripletVec(plVec, psVec, pcVec)

        return res

    def Permutate(self, res, a, b, permMode):
        '''
            SPN-based round transformation
            input: 
                res: 5 elements in list (each element is 64 bits)
                a, b: integers
            output: 5 element list where each element is 64 bits
        '''
        return self._permutate(res, a, b, permMode)

if __name__ == '__main__':
    plainText = "WAITFORMYHOMECOM" # should be multiples of 16 characters use pkcv7
    keyText = "SAMXSAMXSAMXSAMX"
    nonceText = "JAZZJAZZJAZZJAZZ"
    associatedDataText = "WAITFORMYHOMECOMINGWELOMETOTHEFUTURE"
    tagText = "DANXDANXDANXDANX"

    ascon = ASCON()

    cipherText, tagText = ascon.Encrypt(plainText, keyText, associatedDataText, nonceText)
    print ("cipherText: {}, tagText: {}".format(cipherText, tagText))

    plainText = ascon.Decrypt(cipherText, keyText, associatedDataText, nonceText, tagText)
    print ("plainText: {}".format(plainText))


