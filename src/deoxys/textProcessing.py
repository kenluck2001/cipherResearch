from collections import namedtuple
import random
from enum import Enum

BYTE_SIZE = 8

class TEXTHANDLER:
    """
        This is for handling textual data.
    """
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

if __name__ == '__main__':
    txtHandler = TEXTHANDLER()
    textVec =  txtHandler.GenerateVecFromText("KENNETH ODOH IS GREAT")
    print ("textVec: {}".format(textVec))

    hexValue = "6bc0f5"
    print ("Hex string: {} is binary: {}".format(hexValue, txtHandler.GenerateBinaryTextFromHex(hexValue)))

