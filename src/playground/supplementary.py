import codecs

def ConvertHexToBase64(hex):
    '''
        Challenge 1
        https://cryptopals.com/sets/1/challenges/1
        Convert hex to base64
    '''
    b64 = codecs.encode(codecs.decode(hex, 'hex'), 'base64').decode()
    return b64

def XorTwoStr(str1, str2):
    '''
    Challenge 2
    https://cryptopals.com/sets/1/challenges/2
    Convert hex to base64
    '''
    assert len(str1) == len(str2) 
    return hex(int(str1, 16) ^ int(str2, 16))

def SingleByteXORCipher2(hexStr):
    '''
        Challenge 3
        https://cryptopals.com/sets/1/challenges/3
        Single-byte XOR cipher
        Result is \x00 which is unprintable
    '''
    encodedHexStr = "0x" + hexStr
    for i in range (128):
        if (int(encodedHexStr, 16) ^ int(hex(ord(chr(i))), 16)) == int(encodedHexStr, 16):
            print ('key: {0}, encodedHexStr: {1}, char index: {2}'.format(chr(i), encodedHexStr, i))
            break

def ProcessFileSearchForSingleByteXORCipher2(filename = "hexlist.txt"):
    '''
        Challenge 4
        https://cryptopals.com/sets/1/challenges/4
        Single-byte XOR cipher
    '''
    with open(filename) as f:
        lines = f.readlines()
        # read string line by line
        for line in lines:
            SingleByteXORCipher2(line)

def EncryptByRepeatingPatternKeyXOR(msg, key):
    '''
        Challenge 5
        https://cryptopals.com/sets/1/challenges/5
        Implement repeating-key XOR
    '''
    assert len(key) < len(msg)
    factor = int (len(msg) / len(key) ) + 1
    augmentedKey = key * factor # repeating string patterns
    augmentedKey = augmentedKey[: len(msg)]
    print (augmentedKey)
    crytotext = "".join([chr(ord(c1) ^ ord(c2)) for (c1,c2) in zip(msg, augmentedKey)])
    return codecs.encode(crytotext, "hex")

def convertRandomStringToBin (s1):
    s1str = "".join([chr(ord(c1)) for c1 in s1])
    s1str = codecs.encode(s1str, "hex")
    s1str = bin(int(s1str, 16))[2:]
    return s1str

def hamming2(s1, s2):
    """Calculate the Hamming distance between two bit strings"""
    #assert len(s1) == len(s2)
    s1str = convertRandomStringToBin (s1)
    s2str = convertRandomStringToBin (s2)
    return sum(c1 != c2 for c1, c2 in zip(s1str, s2str))

# len('ciao'.encode('utf-16-le'))
# len('ciao'.encode('utf-16')) # converting string to bytes

if __name__ == '__main__':
    originalResult = u'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\n'
    expectedResult = ConvertHexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")

    assert originalResult == expectedResult, "results don't match, provided: {}, expected: {}".format(originalResult, expectedResult) 

    originalResult = '0x746865206b696420646f6e277420706c6179L'
    expectedResult = XorTwoStr("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")

    assert originalResult == expectedResult, "results don't match, provided: {}, expected: {}".format(originalResult, expectedResult) 

    originalResult = "\x00" 
    expectedResult = SingleByteXORCipher2("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

    #ProcessFileSearchForSingleByteXORCipher2()

    EncryptByRepeatingPatternKeyXOR("Burning 'em, if you ain't quick and nimble", "ICE")
    EncryptByRepeatingPatternKeyXOR("I go crazy when I hear a cymbal", "ICE")

    originalResult = 37
    expectedResult = hamming2("this is a test", "wokka wokka!!!")

    assert originalResult == expectedResult, "results don't match, provided: {}, expected: {}".format(originalResult, expectedResult)
