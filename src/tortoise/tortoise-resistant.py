from collections import namedtuple
from enum import Enum
from aes import AES, Version as aesVersion
from textProcessing import TEXTHANDLER

class TORTOISE:
    """
        TORTOISE (Nonce-misuse resistant)
        Implementation uses padding Pkcv7 padding with a tweakable cipher, 
        as described in paper ( https://people.csail.mit.edu/rivest/pubs/LRW02.pdf)
    """
    def __init__(self):
        Param = namedtuple('Param', ['n', 'N'])

        # Adding settings
        self.settings = Param(128,  120)
        self.aes = AES()
    
        self.txtHandler = TEXTHANDLER()

    def ProcessAssociatedData(self, associatedDataText, keyText):
        '''
            Processing associated data layer
            input: 
                associatedDataText: arbitrary length of additional text
                keyText: 128 bits (16 alphabets characters)
            output:
                authText is alphabets
        '''
        n = self.settings.n
        authBin = '0'*n
        authVec = self.txtHandler.GenerateVecFromBinaryText(authBin, SET_BYTE_SIZE=n)
        assocDataVec, _ = self.PaddingMessageBlocks(associatedDataText)

        s = len(assocDataVec)
        for ind in range(s):
            aDataVec = [assocDataVec[ind]]
            authVec = self.__makeAuth(aDataVec, authVec, keyText, ind, n)

        authBin = self.txtHandler.ConvertVecToBinary(authVec, SET_BYTE_SIZE=n)    
        authText = self.txtHandler.getAlphabetFromBinaryText (authBin)

        return authText

    def __makeAuth(self, aDataVec, authVec, keyText, ind, n):
        aDataBin = self.txtHandler.ConvertVecToBinary(aDataVec, SET_BYTE_SIZE=n)    
        aDataText = self.txtHandler.getAlphabetFromBinaryText (aDataBin)

        tweakBin = "{}{}".format('0010', bin(ind)[2:].zfill(n - 4))
        tweakText = self.txtHandler.getAlphabetFromBinaryText(tweakBin)

        cipherText = self.aes.EncryptTweak(tweakText, aDataText, keyText)
        cipherBin = self.txtHandler.ConvertAlphabetsToBinary(cipherText)
        cipherVec = self.txtHandler.GenerateVecFromBinaryText(cipherBin, SET_BYTE_SIZE=n)

        authVec = self.txtHandler.VectoredXor(authVec, cipherVec)
        
        return authVec

    def __messageAuthAndTagGeneration(self, plainTxtVec, tagVec, keyText, ind, n):
        plainTxtBin = self.txtHandler.ConvertVecToBinary(plainTxtVec, SET_BYTE_SIZE=n)    
        pText = self.txtHandler.getAlphabetFromBinaryText (plainTxtBin)
        tweakBin = "{}{}".format( '0000', bin(ind)[2:].zfill(n - 4) )
        tweakText = self.txtHandler.getAlphabetFromBinaryText(tweakBin)
        cipherText = self.aes.EncryptTweak(tweakText, pText, keyText)
        cipherBin = self.txtHandler.ConvertAlphabetsToBinary(cipherText)
        cipherVec = self.txtHandler.GenerateVecFromBinaryText(cipherBin, SET_BYTE_SIZE=n)
        tagVec = self.txtHandler.VectoredXor(tagVec, cipherVec)
        
        return tagVec

    def __messageEncryption (self, plainTxtVec, tagText, keyText, ind, n, N):
        plainTxtBin = self.txtHandler.ConvertVecToBinary(plainTxtVec, SET_BYTE_SIZE=n)    
        plainVec = self.txtHandler.GenerateVecFromBinaryText(plainTxtBin, SET_BYTE_SIZE=n)

        tagBin = self.txtHandler.ConvertAlphabetsToBinary(tagText)
        tagVec = self.txtHandler.GenerateVecFromBinaryText(tagBin, SET_BYTE_SIZE=n)

        suffixTweakBin = bin(ind)[2:].zfill(n)
        suffixTweakVec = self.txtHandler.GenerateVecFromBinaryText(suffixTweakBin, SET_BYTE_SIZE=n)
        tweakVec = self.txtHandler.VectoredXor(tagVec, suffixTweakVec)

        tweakBin = self.txtHandler.ConvertVecToBinary(tweakVec, SET_BYTE_SIZE=n)    
        tweakText = self.txtHandler.getAlphabetFromBinaryText(tweakBin)

        nonceBin = self.txtHandler.ConvertAlphabetsToBinary(nonceText).zfill(N)
        pBin = "{}{}".format("0"*8, nonceBin)
        pText = self.txtHandler.getAlphabetFromBinaryText(pBin)

        tweakCipherText = self.aes.EncryptTweak(tweakText, pText, keyText)
        tweakCipherBin = self.txtHandler.ConvertAlphabetsToBinary(tweakCipherText)
        tweakCipherVec = self.txtHandler.GenerateVecFromBinaryText(tweakCipherBin, SET_BYTE_SIZE=n)

        cipherVec = self.txtHandler.VectoredXor(plainVec, tweakCipherVec)
        cipherBin = self.txtHandler.ConvertVecToBinary(cipherVec, SET_BYTE_SIZE=n)
        
        return cipherBin

    def __finalizeTag (self, tagVec, nonceText, keyText, n, N):
        tagBin = self.txtHandler.ConvertVecToBinary(tagVec, SET_BYTE_SIZE=n)    
        tagText = self.txtHandler.getAlphabetFromBinaryText (tagBin)
        nonceBin = self.txtHandler.ConvertAlphabetsToBinary(nonceText).zfill(N)
        tweakBin = "{}{}{}".format( '0001','0000', nonceBin )
        tweakText = self.txtHandler.getAlphabetFromBinaryText(tweakBin)
        tagText = self.aes.EncryptTweak(tweakText, tagText, keyText)

        return tagText

    def ProcessPlainText(self, plainText, nonceText, keyText, authText):
        '''
            Processing plaintext
            input: 
                plainText: arbitrary length of additional text
                keyText: 128 bits (16 alphabets characters)
                nonceText: max 120 bits in alphabet
                authText: alphabet of n bits
            output:
             return a tuple of (cipherText, tagText) in alphabets
        '''
        n = self.settings.n
        N = self.settings.N
        plainTextVec, _ = self.PaddingMessageBlocks(plainText)
        authBin = self.txtHandler.ConvertAlphabetsToBinary(authText)
        tagVec = self.txtHandler.GenerateVecFromBinaryText(authBin, SET_BYTE_SIZE=n)

        cipherBlockLst = []
        t = len(plainTextVec)

        # message authenticationand tag generation
        for ind in range(t):
            plainTxtVec = [plainTextVec[ind]]
            tagVec = self.__messageAuthAndTagGeneration(plainTxtVec, tagVec, keyText, ind, n)
        tagText = self.__finalizeTag (tagVec, nonceText, keyText, n, N)

        # message encryption
        for ind in range(t):
            plainTxtVec = [plainTextVec[ind]]
            cipherBin = self.__messageEncryption (plainTxtVec, tagText, keyText, ind, n, N)
            cipherBlockLst.append (cipherBin)

        cipherText = "".join([self.txtHandler.getAlphabetFromBinaryText (textBin) for textBin in cipherBlockLst])

        return cipherText, tagText

    def ProcessCipherText(self, cipherText, nonceText, keyText, tagText, authText):
        '''
            Processing cipher text
            input: 
                cipherText: arbitrary length of additional text
                keyText: 128 bits (16 alphabets characters)
                nonceText: 64 bits or 120 bits in alphabet
                tagText: alphabet of n bits
                authText: alphabet of n bits
            output:
             return a tuple of (plainText, tagText) in alphabets
        '''
        n = self.settings.n
        N = self.settings.N

        tagBin = self.txtHandler.ConvertAlphabetsToBinary(tagText)
        tagVec = self.txtHandler.GenerateVecFromBinaryText(tagBin, SET_BYTE_SIZE=n)
        tagText = self.txtHandler.getAlphabetFromBinaryText (tagBin)
        cipherTextVec, lengthCipherInChars = self.PaddingMessageBlocks(cipherText)

        plainBlockLst = []
        t = len(cipherTextVec)
        for ind in range(t):
            cipherTxtVec = [cipherTextVec[ind]]
            plainBin = self.__messageEncryption (cipherTxtVec, tagText, keyText, ind, n, N)
            plainBlockLst.append (plainBin)

        # message authenticationand tag generation
        tagBin = self.txtHandler.ConvertAlphabetsToBinary(authText)
        tagVec = self.txtHandler.GenerateVecFromBinaryText(tagBin, SET_BYTE_SIZE=n)

        for ind in range(t):
            plainTxtBin = plainBlockLst[ind]
            plainTxtVec = self.txtHandler.GenerateVecFromBinaryText(plainTxtBin, SET_BYTE_SIZE=n)
            tagVec = self.__messageAuthAndTagGeneration(plainTxtVec, tagVec, keyText, ind, n)

        tagText = self.__finalizeTag (tagVec, nonceText, keyText, n, N)

        plainText = "".join([self.txtHandler.getAlphabetFromBinaryText (textBin) for textBin in plainBlockLst])

        return plainText[: lengthCipherInChars], tagText

    def VerifyTag(self, providedtagText, tagText):
        '''
            Verifying tag
            input: 
                providedtagText: 128 bits (16 alphabets characters)
                tagText: 128 bits (16 alphabets characters)
            output: true or false
        '''
        print ("tagAlphabet: {}, tagText: {}".format(providedtagText, tagText))

        return providedtagText == tagText

    def PaddingMessageBlocks(self, text):
        '''
            Pad the message blocks
            input:
                text: string of alphabets of arbitrary length
                phase: enum with value of encrypt, decrypt
            output: tuple of (textBinVec, lenOfChars)
        '''
        n = self.settings.n
        sizeInBytes = n // 8
        lenOfChars = len(text)
        quantizedLenOfChars = ((lenOfChars // sizeInBytes) + 1) * sizeInBytes
        numOfChars = quantizedLenOfChars if (lenOfChars % sizeInBytes) > 0 else lenOfChars
        text = self.__padUsingPKCV7(text, characterCount = numOfChars)
        textBin = self.txtHandler.ConvertAlphabetsToBinary(text)
        textBinVec = self.txtHandler.GenerateVecFromBinaryText(textBin, SET_BYTE_SIZE=n)

        return textBinVec, lenOfChars

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
            output: return a tuple of cipher text of alphabets, and tag composed of alphabets
        '''

        # pad using PKCV7 to 128 bits
        keyText = self.__padUsingPKCV7(keyText)

        authText = self.ProcessAssociatedData(associatedDataText, keyText)
        cipherText, tagText = self.ProcessPlainText(plainText, nonceText, keyText, authText)

        # pad using PKCV7
        tagText = self.__padUsingPKCV7(tagText)

        # reset the state
        return cipherText, tagText

    def Decrypt(self, cipherText, keyText, associatedDataText, tagText, nonceText):
        '''
            input: 
                cipherText: arbitrary length of additional text
                keyText: 128 bits (16 alphabets characters)
                associatedDataText: arbitrary length of additional text
                tagText: 128 bits (16 alphabets characters)
            output: return a tuple of plaintext of alphabets, and tag composed of alphabets
        '''
        self.stateVec = None # stateVec: 5 elements in list (each element is 64 bits)
        # pad using PKCV7
        keyText = self.__padUsingPKCV7(keyText)
        tagText = self.__padUsingPKCV7(tagText)

        authText = self.ProcessAssociatedData(associatedDataText, keyText)
        plainText, recreatedTagText = self.ProcessCipherText(cipherText, nonceText, keyText, tagText, authText)

        tagStatus = self.VerifyTag(recreatedTagText, tagText)

        if not tagStatus:
            #raise Exception("MAC (signature matching failed)") 
            print ("There is forgery in the message, signature mismatch")
            return None

        return plainText

if __name__ == '__main__':
    #plainText = "WAITFORMYHOMECOM" # should be multiples of 16 characters use pkcv7
    plainText = "WAITFORM" # should be multiples of 16 characters use pkcv7
    keyText = "SAMXSAMXSAMXSAMX"
    nonceText = "JAZZJAZZ"
    associatedDataText = "WAITFORMYHOMECOMINGWELOMETOTHEFUTURE"
    tagText = "DANXDANXDANXDANX"

    tortoise = TORTOISE()

    cipherText, tagText = tortoise.Encrypt(plainText, keyText, associatedDataText, nonceText)
    print ("cipherText: {}, tagText: {}".format(cipherText, tagText))

    plainText = tortoise.Decrypt(cipherText, keyText, associatedDataText, tagText, nonceText)
    print ("plainText: {}".format(plainText))


