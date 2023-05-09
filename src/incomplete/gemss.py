import random
import numpy as np
import scipy.linalg as la
from collections import namedtuple
# Import math Library
import math 
random.seed(10)

# 
def CreatePolynomial (xVec, n, D, vVec, seed = 0):
    '''
        Create polynomial with HFEv-shape of degree D
    '''
    np.random.seed(seed)
    aMat = np.random.randint(np.power(n, 2), size=(n, n))
    sumPart1 = 0
    for i in range (n):
        for j in range (i+1, n):
            exp = (2**i) + (2**j)
            if (exp <= D):
                cVal = xVec**exp
                sumPart1 += (aMat[i][j] * cVal)

    #print ("sumPart1.shape: {}, aMat.shape: {}".format(sumPart1.shape, aMat.shape))

    sampleList = lambda cnt : random.sample(range(0, n), cnt) 
    # create field extension
    denPoly = [0]*(n+1)
    denPoly[0] = 1
    denPoly[-(13+1)] = 1
    denPoly[n] = 1
    betaPolyList = [np.poly1d(np.polydiv(sampleList(2), denPoly)[1]) for _ in range(n)] # linear
    sumPart2 = 0
    for i, curPoly in enumerate(betaPolyList):
        exp = 2**i
        if (exp <= D):
            cVal = xVec**exp
            sumPart2 += ((np.sum(curPoly(vVec)) % 2**n) * cVal)

    gammaPoly = np.poly1d(np.polydiv(sampleList(3), denPoly)[1]) # quadratic
    sumPart3 = np.sum(gammaPoly(vVec))
    sumVec = sumPart1 + sumPart2 + sumPart3

    sumVec = sumVec % 2**n

    xSumVecWithVinegar = np.hstack((sumVec, vVec))

    return xSumVecWithVinegar

def CreateInvertibleMatrix (n, seed=0 ):
    np.random.seed(seed)
    a = np.random.randint(2, size=(n, n))
    (P, L, U) = la.lu(a)
    L[range(n), range(n)] = 1
    U[range(n), range(n)] = 1
    return L * U

def GeMMSKeyGen(xVec, n, D, vVec, delta = 0):
    v = len(vVec)
    sMat = CreateInvertibleMatrix(n+v) # n x (n+v)
    tMat = CreateInvertibleMatrix(n)   # n x n

    funcSeed = []
    flist = []
    for ind in range(n):
        cSeed = ind * 1000
        funcSeed.append(cSeed)
        fPolynomial = CreatePolynomial (xVec, n, D, vVec, seed = cSeed)
        thetaVec = getTheta (n, seed=cSeed)
        fPolynomial[:n] = np.multiply (thetaVec, fPolynomial[:n])

        flist.append (fPolynomial.tolist())

    fMat = np.asmatrix(flist)  # n x (n+v)

    print ("fMat.shape: {}".format(fMat.shape))
    cumMat = np.matmul(tMat, fMat)
    print ("cumMat.shape: {}, tMat.shape: {}, fMat.shape: {}".format(cumMat.shape, tMat.shape, fMat.shape))
    cumMat = np.matmul(cumMat, sMat).astype(int)

    xVecVinegar = np.hstack((xVec, vVec))
    xVecVinegarWithSquare = np.square(xVecVinegar)
    xVecVinegarDiff = xVecVinegarWithSquare - xVecVinegar  

    print ("cumMat : {}".format(cumMat.astype(int)))

    m = n - delta
    SecretKey = namedtuple('SecretKey', ['funcSeeds', 'sMat', 'tMat'])
    sKey  = SecretKey(funcSeed, sMat, tMat)

    resDict = {}
    resDict["pk"] = cumMat[range(m), :]   
    resDict["sk"] = sKey
    return resDict

def getTheta (n, seed=0):
    np.random.seed(seed)
    thetaVec = np.random.randint(1024, size=n, dtype=np.int64) + 2**n - 1024
    return thetaVec

def Totient(iVec, n, seed=0):
    thetaVec = getTheta (n, seed=seed)
    return np.dot(thetaVec.T, iVec)

def InverseTotient(iVec, n, seed=0):
    thetaVec = getTheta (n, seed=seed)
    invThetaVec = 1.0 / thetaVec
    return np.dot(invThetaVec.T, iVec)

def GeMSSInv(dVec, sk, n, vCnt, delta):
    '''
        input: 
            dVec is a vector of m size
    '''
    _rVec = None
    tMat = sk.tMat
    sMat = sk.sMat
    funcSeeds = sk.funcSeeds
    tMatInv = np.linalg.inv(tMat) 
    sMatInv = np.linalg.inv(sMat) 

    while True:
        m = n - delta
        rVec = np.random.randint(2, size=(n - m))
        dhat = np.hstack((dVec, rVec))

        print("dhat.shape: {}, tMatInv.shape: {}".format(dhat.shape, tMatInv.shape))
        dhatProdTmat = np.matmul(dhat, tMatInv)

        dHatVal = InverseTotient(dhatProdTmat, n)
        vVec = np.random.randint(2, size=vCnt)

        for seed in funcSeeds:
            fPolynomial = CreatePolynomial (xVec, n, D, vVec, seed = seed)
            thetaVec = getTheta (n, seed=seed)
            cv = np.dot (thetaVec.T, fPolynomial[:n]) + np.sum(fPolynomial[n:])

            # Confused on how to find root
            if abs(dHatVal - cv) <= 10:
                _rVec = rVec
            print ("cv: {}".format(cv))

        if not _rVec:
            print ("root does not exist")
            return

    thetaVec = getTheta (n)
    dVec = np.multiply (thetaVec, dVec)

    dhat = np.hstack((dVec, _rVec))
    return np.matmul(dhat, sMatInv)


if __name__ == "__main__":
    xVec = np.random.randint(2, size=100)
    vVec = np.random.randint(2, size=20)

    n, D = 100, 513
    vec = CreatePolynomial (xVec, n, D, vVec)
    print ("vec: {}, vec.shape: {}".format(vec, vec.shape))

    res = GeMMSKeyGen(xVec, n, D, vVec)
    print ("res: {}".format(res))

    print ("sk.funcSeeds: {}".format(res["sk"].funcSeeds))
    print ("sk.sMat: {}".format(res["sk"].sMat))
    print ("sk.tMat: {}".format(res["sk"].tMat))

    sk = res["sk"]
    dVec = np.random.randint(2, size=100)
    delta = 0
    vCnt = 20
    res = GeMSSInv(dVec, sk, n, vCnt, delta)

    print ("GeMSSInv: {}".format(res))



