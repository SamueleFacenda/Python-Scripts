from Crypto.Util.number import getPrime, inverse, long_to_bytes, bytes_to_long


class RSA:
    def __init__(self, nbits, e=-1):
        p, q = getPrime(nbits//2), getPrime(nbits//2)
        N = p*q
        self.phi = (p-1)*(q-1)
        d = inverse(e,self.phi)

        self.N = N
        self.e = e
        self.d = d

    def encrypt(self, data):
        m = bytes_to_long(data)
        c = pow(m, self.e, self.N)
        return long_to_bytes(c)

    def decrypt(self, data):
        c = bytes_to_long(data)
        m = pow(c, self.d, self.N)
        return long_to_bytes(m)

r = RSA(2048)
print(r.phi, r.d)

N = 15761696848277146240220170349153208659450329266072524719236431720789636378853244291428358990415259673549517077469211924515483732020527197787851770155686589521637147514344912873609085293046613003246243830498095228858516120792708944055254822701488120684764826007679159424664423368766660756415494990401731476945297028728352184255206345834923734785230215986465807425597155477517063934877179576460995237796181533624257456816765006880573493162655849893840723838895424520475949085458743325302944280880961705884935902211039304686139566410299263827476969433755116540895058638630865634579944248572615610303648070774889858467017
flag_enc = "7681bb9a7eac3a339d193eda4b918935145266bc947cdf8296c374ece9f112dfdc2573af902c48b2ea1e87c80f5a64ae809cfb552269793eb1a022ba771f5845d0ecb8e517dff03db7ec17be348b5b8886bb77dc5d5fceaede635a913cc492e6573603b97d9b054e027f0fcb2549b31f03d4425534c64649d7517f0ffcbea3778cfbfb8e6ab4c4f3358ae3719e75646dcdfd1176421f37700205ad279a339cf1516cc4566ab5aa400511de05b5b0148b4efc469d0c916fcf64830cfd08cd64b0708dc11ca3449d52406dbaacba975d4043c06fc54c80462f0535f4b4334b12c46e665b809cfc6b20af4c7e827ce431e66725b12210b2ad521fa27de75d91d570"


c = bytes_to_long(bytes.fromhex(flag_enc))
m = pow(c, -1, N)
print(long_to_bytes(m))
