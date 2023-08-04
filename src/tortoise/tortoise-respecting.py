from collections import namedtuple
from enum import Enum
from aes import AES, Version as aesVersion
from textProcessing import TEXTHANDLER

class TORTOISE:
    """
        TORTOISE (Nonce-respecting)
        Implementation uses padding Pkcv7 padding with a tweakable cipher, 
        as described in paper ( https://people.csail.mit.edu/rivest/pubs/LRW02.pdf)
    """
    def __init__(self):
        Param = namedtuple('Param', ['n', 'N'])

        # Adding settings
        self.settings = Param(128,  64)
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
            aDataBin = self.txtHandler.ConvertVecToBinary(aDataVec, SET_BYTE_SIZE=n)    
            aDataText = self.txtHandler.getAlphabetFromBinaryText (aDataBin)

            tweakBin = "{}{}".format('0010', bin(ind)[2:].zfill(n - 4))
            tweakText = self.txtHandler.getAlphabetFromBinaryText(tweakBin)

            cipherText = self.aes.EncryptTweak(tweakText, aDataText, keyText)
            cipherBin = self.txtHandler.ConvertAlphabetsToBinary(cipherText)
            cipherVec = self.txtHandler.GenerateVecFromBinaryText(cipherBin, SET_BYTE_SIZE=n)

            authVec = self.txtHandler.VectoredXor(authVec, cipherVec)

        authBin = self.txtHandler.ConvertVecToBinary(authVec, SET_BYTE_SIZE=n)    
        authText = self.txtHandler.getAlphabetFromBinaryText (authBin)

        return authText

    def ProcessPlainText(self, plainText, nonceText, keyText):
        '''
            Processing plaintext
            input: 
                plainText: arbitrary length of additional text
                keyText: 128 bits (16 alphabets characters)
                nonceText: 64 bits or 120 bits in alphabet
            output:
             return a tuple of (cipherText, finalText) in alphabets
        '''
        n = self.settings.n
        N = self.settings.N
        finalText = None
        checksumBin = '0'*n
        checksumVec = self.txtHandler.GenerateVecFromBinaryText(checksumBin, SET_BYTE_SIZE=n)
        plainTextVec, _ = self.PaddingMessageBlocks(plainText)

        cipherBlockLst = []
        t = len(plainTextVec)
        for ind in range(t):
            plainTxtVec = [plainTextVec[ind]]
            checksumVec = self.txtHandler.VectoredXor(checksumVec, plainTxtVec)
            plainTxtBin = self.txtHandler.ConvertVecToBinary(plainTxtVec, SET_BYTE_SIZE=n)    
            pText = self.txtHandler.getAlphabetFromBinaryText (plainTxtBin)
            nonceBin = self.txtHandler.ConvertAlphabetsToBinary(nonceText).zfill(N)
            tweakBin = "{}{}{}".format( '0000', nonceBin, bin(ind)[2:].zfill(n - N - 4) )
            tweakText = self.txtHandler.getAlphabetFromBinaryText(tweakBin)

            cipherText = self.aes.EncryptTweak(tweakText, pText, keyText)

            cipherBin = self.txtHandler.ConvertAlphabetsToBinary(cipherText)
            cipherBlockLst.append (cipherBin)

        checksumBin = self.txtHandler.ConvertVecToBinary(checksumVec, SET_BYTE_SIZE=n)    
        checksumText = self.txtHandler.getAlphabetFromBinaryText (checksumBin)

        nonceBin = self.txtHandler.ConvertAlphabetsToBinary(nonceText).zfill(N)
        tweakBin = "{}{}{}".format( '0001', nonceBin, bin(t)[2:].zfill(n - N - 4) )
        tweakText = self.txtHandler.getAlphabetFromBinaryText(tweakBin)
        finalText = self.aes.EncryptTweak(tweakText, checksumText, keyText)

        cipherText = "".join([self.txtHandler.getAlphabetFromBinaryText (textBin) for textBin in cipherBlockLst])

        return cipherText, finalText

    def ProcessCipherText(self, cipherText, nonceText, keyText):
        '''
            Processing cipher text
            input: 
                cipherText: arbitrary length of additional text
                keyText: 128 bits (16 alphabets characters)
                nonceText: 64 bits or 120 bits in alphabet
            output:
             return a tuple of (plainText, finalText) in alphabets
        '''
        n = self.settings.n
        N = self.settings.N
        finalText = None
        checksumBin = '0'*n
        checksumVec = self.txtHandler.GenerateVecFromBinaryText(checksumBin, SET_BYTE_SIZE=n)
        cipherTextVec, lengthCipherInChars = self.PaddingMessageBlocks(cipherText)

        plainBlockLst = []
        t = len(cipherTextVec)
        for ind in range(t):
            cipherTxtVec = [cipherTextVec[ind]]
            cipherBin = self.txtHandler.ConvertVecToBinary(cipherTxtVec, SET_BYTE_SIZE=n)    
            cipherText = self.txtHandler.getAlphabetFromBinaryText (cipherBin)
            nonceBin = self.txtHandler.ConvertAlphabetsToBinary(nonceText).zfill(N)
            tweakBin = "{}{}{}".format( '0000', nonceBin, bin(ind)[2:].zfill(n - N - 4) )
            tweakText = self.txtHandler.getAlphabetFromBinaryText(tweakBin)

            plainText = self.aes.DecryptTweak(tweakText, cipherText, keyText)
            plainBin = self.txtHandler.ConvertAlphabetsToBinary(plainText)
            plainTxtVec = self.txtHandler.GenerateVecFromBinaryText(plainBin, SET_BYTE_SIZE=n)
            checksumVec = self.txtHandler.VectoredXor(checksumVec, plainTxtVec) 
            plainBlockLst.append (plainBin)

        checksumBin = self.txtHandler.ConvertVecToBinary(checksumVec, SET_BYTE_SIZE=n)    
        checksumText = self.txtHandler.getAlphabetFromBinaryText (checksumBin)


        nonceBin = self.txtHandler.ConvertAlphabetsToBinary(nonceText).zfill(N)
        tweakBin = "{}{}{}".format( '0001', nonceBin, bin(t)[2:].zfill(n - N - 4) )
        tweakText = self.txtHandler.getAlphabetFromBinaryText(tweakBin)

        finalText = self.aes.EncryptTweak(tweakText, checksumText, keyText)

        plainText = "".join([self.txtHandler.getAlphabetFromBinaryText (textBin) for textBin in plainBlockLst])

        return plainText[: lengthCipherInChars], finalText

    def GetTag(self, finalText, authText):
        '''
            Obtain tag
            input: 
                finalText: 128 bits (16 alphabets characters)
                authText : 128 bits (16 alphabets characters)
            output: 16 alphabets characters
        '''
        n = self.settings.n

        finalBin = self.txtHandler.ConvertAlphabetsToBinary(finalText)
        finalVec = self.txtHandler.GenerateVecFromBinaryText(finalBin, SET_BYTE_SIZE=n)

        authBin = self.txtHandler.ConvertAlphabetsToBinary(authText)
        authVec = self.txtHandler.GenerateVecFromBinaryText(authBin, SET_BYTE_SIZE=n)

        tagVec = self.txtHandler.VectoredXor(finalVec, authVec)
        tagBin = self.txtHandler.ConvertVecToBinary(tagVec, SET_BYTE_SIZE=n)
        tagAlphabet = self.txtHandler.ConvertBinaryToAlphabet(tagBin)

        return tagAlphabet

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
            output: tuple of ()
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
        cipherText, finalText = self.ProcessPlainText(plainText, nonceText, keyText)

        tagText = self.GetTag(finalText, authText)
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
        plainText, finalText = self.ProcessCipherText(cipherText, nonceText, keyText)
        recreatedTagText = self.GetTag(finalText, authText)
        tagStatus = self.VerifyTag(recreatedTagText, tagText)

        if not tagStatus:
            #raise Exception("MAC (signature matching failed)") 
            print ("There is forgery in the message, signature mismatch")
            return None

        return plainText

if __name__ == '__main__':
    #plainText = "WAITFORMYHOMECOM" # should be multiples of 16 characters use pkcv7
    plainText = "WAITFORMC" # should be multiples of 16 characters use pkcv7
    keyText = "SAMXSAMXSAMXSAMX"
    nonceText = "JAZZJAZZ"
    associatedDataText = "WAITFORMYHOMECOMINGWELOMETOTHEFUTURE"
    tagText = "DANXDANXDANXDANX"

    tortoise = TORTOISE()

    cipherText, tagText = tortoise.Encrypt(plainText, keyText, associatedDataText, nonceText)
    print ("cipherText: {}, tagText: {}".format(cipherText, tagText))

    plainText = tortoise.Decrypt(cipherText, keyText, associatedDataText, tagText, nonceText)
    print ("plainText: {}".format(plainText))



