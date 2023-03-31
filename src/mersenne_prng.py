import math
SEED = 5489

class MersenneTwisterPRNG:
    """
        Mersenne Twister PRNG
        Reference: https://en.wikipedia.org/wiki/Mersenne_Twister
    """
    def __init__(self):
        self.w = 10
        self.n = 1000 
        self.m = 20
        self.r = 5
        self.a = 10000
        self.u = 4
        self.d = 9999 
        self.s = 6 
        self.b = 999999 
        self.t = 89999
        self.c = 49996
        self.l = 7
        self.f = 7599

        upperLimit = (1 << ((self.n * self.w) - self.r)) - 1
        self.bits = int(math.ceil( math.log(upperLimit) / math.log(2) ))

        # Create a length n array to store the state of the generator
        self.MT = [0 for _ in range(self.n)]
        self.index = self.n+1
        self.lower_mask = (1 << self.r) - 1 # That is, the binary number of r 1's
        cVal = self.negateValueWithinSpecifiedNumOfbits(self.lower_mask, bits=self.bits)
        self.upper_mask = self.lowestWbits( cVal, self.w )

    def negateValueWithinSpecifiedNumOfbits(self, val, bits=8):
        bitmask = int("1"*bits, 2)
        return (~val & bitmask)

    def lowestWbits(self, val, w):
        return ((1 << w) - 1) & val

    # Initialize the generator from a seed
    def seedMt(self, seed):
        self.index = self.n
        self.MT[0] = seed
        for i in range(1, self.n):
            cVal = (self.f * (self.MT[i-1] ^ (self.MT[i-1] >> (self.w-2))) + i)
            self.MT[i] = self.lowestWbits( cVal, self.w )

    def rand(self):
        if (self.index >= self.n):
            if (self.index > self.n):
                raise Exception("Generator was never seeded") 
            self.twist()
     
        y = self.MT[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
     
        self.index = self.index + 1
        return self.lowestWbits( y , self.w )
     
    # Generate the next n values from the series x_i 
    def twist(self):
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) | (self.MT[(i+1) % self.n] & self.lower_mask)
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA
        self.index = 0

if __name__ == '__main__':
    rnd = MersenneTwisterPRNG()
    rnd.seedMt(SEED)
    print ("random number: {}".format(rnd.rand()))

