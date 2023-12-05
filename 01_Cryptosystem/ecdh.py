import secrets
import sympy as smp
import time

class My_Point:
    def __init__(self, x:int, y:int):
        self.x = x
        self.y = y

class EC:
    def __init__(self, p:int, a:int, b:int):
        self.Prime = p
        self.a = a
        self.b = b
    
class ECDH_client:
    def __init__(self, bitsize:int):
        self.bitsize = bitsize
        self.curve = None
        self.gen_point = None
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
    
    def is_ab_ok(self, a:int, b:int, prime:int) -> bool:
        rem = (4 * pow(a,3,prime) + 27 * pow(b,2,prime)) % prime
        return rem != 0

    def mk_curve_and_gen_point(self, p:int) -> tuple(EC, My_Point):
        x = secrets.randbelow(p-1)
        a = 
        pass

    def scalar_mult(self, curve:EC, generator_point:My_Point, scalar:int) -> My_Point:
        pass

    def mk_keys(self, curve:EC, generator_point:My_Point) -> tuple(int, My_Point):
        pass

    def mk_shared_secret(self)-> My_Point:
        pass