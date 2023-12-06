import secrets
import sympy as smp
import time
import math
import BitVector as bv


class My_Point:
    def __init__(self, x: int, y: int):
        self.x = x
        self.y = y


class EC:
    def __init__(self, p: int, a: int, b: int):
        self.Prime = p
        self.a = a
        self.b = b


class ECDH_client:
    def __init__(self, bitsize: int):
        self.bitsize = bitsize

        self.curve = None
        self.gen_point = None
        self.private_key = None
        self.public_key = None
        self.shared_secret = None

    def is_ab_ok(self, a: int, b: int, prime: int) -> bool:
        if (a is not None) and (b is not None):
            rem = (4 * pow(a, 3, prime) + 27 * pow(b, 2, prime)) % prime
            return rem != 0
        else:
            return False

    def mk_curve_and_gen_point(self, bitsize: int):
        x = None
        y = None
        a = None
        b = None

        prime = smp.nextprime(2**bitsize)

        while (not self.is_ab_ok(a, b, prime)):
            x = secrets.randbelow(prime - 1)
            a = secrets.randbelow(prime-1)
            y = secrets.randbelow(prime-1)
            b = pow(y, 2, prime) - pow(x, 3, prime) - (a * x) % prime

        curve = EC(p, a, b)
        gen_point = My_Point(x, y)
        self.curve = curve
        self.gen_point = gen_point
        return (curve, gen_point)

    def curve_point_add(self, curve: EC, p1: My_Point, p2: My_Point) -> My_Point:
        s = None
        if (p1.x == p2.x and p1.y == p2.y):
            s = ((3*pow(p1.x, 2, curve.Prime) + curve.a) % curve.Prime) * \
                (pow(2, -1, curve.Prime)) * (pow(p1.y, -1, curve.Prime))

        else:
            s = ((p2.y - p1.y) % curve.Prime) * \
                pow((p2.x-p1.x) % curve.Prime, -1, curve.Prime)

        res = My_Point(0, 0)

        res.x = (pow(s, 2, curve.Prime) - p1.x - p2.x) % curve.Prime
        res.y = ((s % curve.Prime) * ((p1.x - res.x) %
                 curve.Prime) - p1.y) % curve.Prime
        return res

    def scalar_mult(self, curve: EC, start: My_Point, scalar: int) -> My_Point:
        res = start
        mplier = bv.BitVector(intVal=scalar)
        i = 1
        while(i < mplier.length()):
            res = self.curve_point_add(curve, res, res)
            if mplier[i] == 1:
                res = self.curve_point_add(curve, res, start)
            i = i +1    
        return res

    def mk_keys(self, curve: EC, generator_point: My_Point) :
        private_key = secrets.randbelow(
            curve.Prime + 1 + int(math.sqrt(curve.Prime)))

        public_key = self.scalar_mult(
            curve, generator_point, scalar=private_key)
        self.private_key = private_key
        self.public_key = public_key
        return (private_key, public_key)

    def mk_shared_secret(self, other_public_key: My_Point, own_private_key: int) -> My_Point:
        shared_secret = self.scalar_mult(
            self.curve, other_public_key, own_private_key)
        self.shared_secret = shared_secret
        return shared_secret
