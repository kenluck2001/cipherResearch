from collections import namedtuple
from enum import Enum
from aes import AES, Version as aesVersion
from textProcessing import TEXTHANDLER

class Version(Enum):
    DEOXYS_I_128_128 = "DEOXYS_I_128_128"
    DEOXYS_I_256_128 = "DEOXYS_I_256_128"
    DEOXYS_II_128_128 = "DEOXYS_II_128_128"
    DEOXYS_II_256_128 = "DEOXYS_II_256_128"

class DEOXYS:
    """
        DEOXYS v1.41
        Reference: https://github.com/kenluck2001/cipherResearch/blob/main/references/deoxysv141.pdf
        Implementation uses padding Pkcv7 padding without using a tweakable cipher, 
        so the nonce is not used. We have essentially ECB with the resulting vulnerabilities.

        For, schemes (paramPerDeoxysII_128x128, paramPerDeoxysII_256x128) only 
        the computation of the tag is update to make it nonce-misuse resistant
    """
    def __init__(self, version = Version.DEOXYS_I_128_128):
        self.version = version
        Param = namedtuple('Param', ['k', 'l', 'n', 'N', 'r'])

        # Adding settings
        paramPerDeoxysI_128x128  = Param(128, 128, 128,  64, 128)
        paramPerDeoxysI_256x128  = Param(256, 128, 128,  64, 128)
        paramPerDeoxysII_128x128  = Param(128, 128, 128,  120, 128)
        paramPerDeoxysII_256x128  = Param(256, 128, 128,  120, 128)

        self.ParamDict = {
            Version.DEOXYS_I_128_128: paramPerDeoxysI_128x128, 
            Version.DEOXYS_I_256_128: paramPerDeoxysI_256x128,
            Version.DEOXYS_II_128_128: paramPerDeoxysII_128x128, 
            Version.DEOXYS_II_256_128: paramPerDeoxysII_256x128,
        }

        self.settings = self.ParamDict[self.version]
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
            # TODO add encryption flow here

            aDataBin = self.txtHandler.ConvertVecToBinary(aDataVec, SET_BYTE_SIZE=n)    
            aDataText = self.txtHandler.getAlphabetFromBinaryText (aDataBin)
            cipherText = self.aes.Encrypt(aDataText, keyText)
            cipherBin = self.txtHandler.ConvertAlphabetsToBinary(cipherText)
            cipherVec = self.txtHandler.GenerateVecFromBinaryText(cipherBin, SET_BYTE_SIZE=n)

            authVec = self.txtHandler.VectoredXor(authVec, cipherVec)

        authBin = self.txtHandler.ConvertVecToBinary(authVec, SET_BYTE_SIZE=n)    
        authText = self.txtHandler.getAlphabetFromBinaryText (authBin)

        return authText

    def ProcessPlainText(self, plainText, keyText):
        '''
            Processing plaintext
            input: 
                plainText: arbitrary length of additional text
                keyText: 128 bits (16 alphabets characters)
            output:
             return a tuple of (cipherText, finalText) in alphabets
        '''
        n = self.settings.n
        finalText = None
        checksumBin = '0'*n
        checksumVec = self.txtHandler.GenerateVecFromBinaryText(checksumBin, SET_BYTE_SIZE=n)
        plainTextVec, _ = self.PaddingMessageBlocks(plainText)

        cipherBlockLst = []
        t = len(plainTextVec)
        for ind in range(t):
            plainTxtVec = [plainTextVec[ind]]
            checksumVec = self.txtHandler.VectoredXor(checksumVec, plainTxtVec)
            # TODO encrypt and 
            plainTxtBin = self.txtHandler.ConvertVecToBinary(plainTxtVec, SET_BYTE_SIZE=n)    
            pText = self.txtHandler.getAlphabetFromBinaryText (plainTxtBin)
            cipherText = self.aes.Encrypt(pText, keyText)
            cipherBin = self.txtHandler.ConvertAlphabetsToBinary(cipherText)
            cipherBlockLst.append (cipherBin)

        checksumBin = self.txtHandler.ConvertVecToBinary(checksumVec, SET_BYTE_SIZE=n)    
        checksumText = self.txtHandler.getAlphabetFromBinaryText (checksumBin)
        finalText = self.aes.Encrypt(checksumText, keyText)

        cipherText = "".join([self.txtHandler.getAlphabetFromBinaryText (textBin) for textBin in cipherBlockLst])

        return cipherText, finalText

    
    def ProcessCipherText(self, cipherText, keyText):
        '''
            Processing cipher text
            input: 
                cipherText: arbitrary length of additional text
            return a list of t-element each a binary string of 128 bits each
        '''
        n = self.settings.n
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
            plainText = self.aes.Decrypt(cipherText, keyText)
            plainBin = self.txtHandler.ConvertAlphabetsToBinary(plainText)
            plainTxtVec = self.txtHandler.GenerateVecFromBinaryText(plainBin, SET_BYTE_SIZE=n)
            checksumVec = self.txtHandler.VectoredXor(checksumVec, plainTxtVec) 
            plainBlockLst.append (plainBin)

        checksumBin = self.txtHandler.ConvertVecToBinary(checksumVec, SET_BYTE_SIZE=n)    
        checksumText = self.txtHandler.getAlphabetFromBinaryText (checksumBin)
        finalText = self.aes.Encrypt(checksumText, keyText)

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

    def Encrypt(self, plainText, keyText, associatedDataText):
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
        cipherText, finalText = self.ProcessPlainText(plainText, keyText)

        tagText = self.GetTag(finalText, authText)
        # pad using PKCV7
        tagText = self.__padUsingPKCV7(tagText)

        # reset the state
        return cipherText, tagText

    def Decrypt(self, cipherText, keyText, associatedDataText, tagText):
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
        plainText, finalText = self.ProcessCipherText(cipherText, keyText)

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
    nonceText = "JAZZJAZZJAZZJAZZ"
    associatedDataText = "WAITFORMYHOMECOMINGWELOMETOTHEFUTURE"
    tagText = "DANXDANXDANXDANX"

    deoxys = DEOXYS()

    cipherText, tagText = deoxys.Encrypt(plainText, keyText, associatedDataText)
    print ("cipherText: {}, tagText: {}".format(cipherText, tagText))

    plainText = deoxys.Decrypt(cipherText, keyText, associatedDataText, tagText)
    print ("plainText: {}".format(plainText))


