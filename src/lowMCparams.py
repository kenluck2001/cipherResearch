# culled from https://github.com/LowMC/lowmc/blob/master/generate_matrices.py
from collections import namedtuple

def getLowMCParameter(blocksize, keysize, rounds):
    ''' Use the parameters `blocksize`, `keysize` and `rounds`
        to create the set of matrices and constants for the corresponding
        LowMC instance.
    '''
    gen = grain_ssg()
    linlayers = []
    for _ in range(rounds):
        linlayers.append(instantiate_matrix(blocksize, blocksize, gen))

    round_constants = []
    for _ in range(rounds):
        constant = [next(gen) for _ in range(blocksize)]
        round_constants.append(constant)

    roundkey_matrices = []
    for _ in range(rounds + 1):
        mat = instantiate_matrix(blocksize, keysize, gen)
        roundkey_matrices.append(mat)

    LowMCParams = namedtuple('LowMCParams', ['LinearLayerMatrix', 'RoundKeyMatrix', 'RoundConstants'])
    lowMCParams  = LowMCParams(linlayers, roundkey_matrices, round_constants)

    return lowMCParams

def instantiate_matrix(n, m, gen):
    ''' Instantiate a matrix of maximal rank using bits from the
        generatator `gen`.
    '''
    while True:
        mat = []
        for _ in range(n):
            row = []
            for _ in range(m):
                row.append(next(gen))
            mat.append(row)
        if rank(mat) >= min(n, m):
            return mat

def rank(matrix):
    ''' Determine the rank of a binary matrix. '''
    # Copy matrix
    mat = [[x for x in row] for row in matrix]
    
    n = len(matrix)
    m = len(matrix[0])
    for c in range(m):
        if c > n - 1:
            return n
        r = c
        while mat[r][c] != 1:
            r += 1
            if r >= n:
                return c
        mat[c], mat[r] = mat[r], mat[c]
        for r in range(c + 1, n):
            if mat[r][c] == 1:
                for j in range(m):
                    mat[r][j] ^= mat[c][j]

    return m

def grain_ssg():
    ''' A generator for using the Grain LSFR in a self-shrinking generator. '''
    state = [1 for _ in range(80)]
    index = 0
    # Discard first 160 bits
    for _ in range(160):
        state[index] ^= state[(index + 13) % 80] ^ state[(index + 23) % 80]\
                        ^ state[(index + 38) % 80] ^ state[(index + 51) % 80]\
                        ^ state[(index + 62) % 80]
        index += 1
        index %= 80
    choice = False
    while True:
        state[index] ^= state[(index + 13) % 80] ^ state[(index + 23) % 80]\
                        ^ state[(index + 38) % 80] ^ state[(index + 51) % 80]\
                        ^ state[(index + 62) % 80]
        choice = state[index]
        index += 1
        index %= 80
        state[index] ^= state[(index + 13) % 80] ^ state[(index + 23) % 80]\
                        ^ state[(index + 38) % 80] ^ state[(index + 51) % 80]\
                        ^ state[(index + 62) % 80]
        if choice == 1:
            yield state[index]
        index += 1
        index %= 80

if __name__ == '__main__':

    blocksize = 128
    keysize = 128
    rounds = 20

    '''
    LinearLayerMatrix.size: 20x128x128
    RoundKeyMatrix.size: 21x128x128
    RoundConstants.size: 20x128
    '''
    param = getLowMCParameter(blocksize, keysize, rounds)
    print ("LinearLayerMatrix.size: {}x{}x{}".format(len(param.LinearLayerMatrix) , len(param.LinearLayerMatrix[0]), len(param.LinearLayerMatrix[0][0]) ))

    print ("RoundKeyMatrix.size: {}x{}x{}".format(len(param.RoundKeyMatrix) , len(param.RoundKeyMatrix[0]), len(param.RoundKeyMatrix[0][0]) ))

    print ("RoundConstants.size: {}x{}".format(len(param.RoundConstants) , len(param.RoundConstants[0]) ))
