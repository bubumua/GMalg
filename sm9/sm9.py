import math
from typing import Tuple, List
from sm3.sm3 import sm3_hash
from sm4.sm4 import sm4_crypt_ecb

# SM9算法参数
# 素数p，用于定义有限域Fp
p = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D

# 椭圆曲线参数
b = 0x20A601907B8C953CA1481EB10512F78744A3205FD

# 扭曲线参数
t = 0x24000000000024000000000001
a = 0

# 生成元P1
P1_x = 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD
P1_y = 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616

# 用于配对运算的参数
N = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25


class Point:
    """椭圆曲线上的点"""

    def __init__(self, x: int, y: int):
        self.x = x
        self.y = y

    def is_infinity(self) -> bool:
        """判断是否为无穷远点"""
        return self.x is None and self.y is None

    @staticmethod
    def infinity() -> 'Point':
        """返回无穷远点"""
        return Point(None, None)


def add_points(P: Point, Q: Point) -> Point:
    """椭圆曲线点加法"""
    if P.is_infinity():
        return Q
    if Q.is_infinity():
        return P

    if P.x == Q.x:
        if (P.y + Q.y) % p == 0:
            return Point.infinity()
        # 点倍
        lam = ((3 * P.x * P.x + a) * pow(2 * P.y, -1, p)) % p
    else:
        # 点加
        lam = ((Q.y - P.y) * pow(Q.x - P.x, -1, p)) % p

    x3 = (lam * lam - P.x - Q.x) % p
    y3 = (lam * (P.x - x3) - P.y) % p

    return Point(x3, y3)


def scalar_multiply(k: int, P: Point) -> Point:
    """标量乘法"""
    Q = Point.infinity()
    k_bin = bin(k)[2:]  # 转换为二进制串

    for bit in k_bin:
        Q = add_points(Q, Q)  # 倍点
        if bit == '1':
            Q = add_points(Q, P)  # 点加

    return Q


class SM9:
    def __init__(self):
        """初始化SM9系统参数"""
        self.P1 = Point(P1_x, P1_y)  # 生成元P1

    def generate_master_key(self) -> Tuple[int, Point]:
        """生成主密钥对"""
        # 随机选择主私钥s
        s = int.from_bytes(sm3_hash(b"master_key_seed").encode(), 'big') % N
        # 计算主公钥 Ppub = s * P1
        Ppub = scalar_multiply(s, self.P1)
        return s, Ppub

    def generate_user_key(self, master_key: int, identity: str) -> Tuple[Point, bytes]:
        """为用户生成私钥"""
        # 计算用户标识hash
        id_hash = sm3_hash(identity.encode())
        # 计算用户私钥
        d = (master_key * int.from_bytes(id_hash.encode(), 'big')) % N
        # 生成随机数用于加密私钥
        r = int.from_bytes(sm3_hash(b"key_encryption_seed").encode(), 'big') % N
        # 使用SM4加密私钥
        key = r.to_bytes(16, 'big')
        encrypted_private_key = sm4_crypt_ecb(key, d.to_bytes(32, 'big'), 0)
        return scalar_multiply(d, self.P1), encrypted_private_key

    def sign(self, private_key: Point, message: bytes) -> Tuple[Point, int]:
        """SM9签名算法"""
        # 生成随机数
        r = int.from_bytes(sm3_hash(message + b"signature_random").encode(), 'big') % N
        # 计算R = r * P1
        R = scalar_multiply(r, self.P1)
        # 计算h = H(M || R)
        h = int.from_bytes(sm3_hash(message + str(R.x).encode() + str(R.y).encode()).encode(), 'big')
        # 计算s = r + h * private_key
        s = (r + h * private_key.x) % N
        return R, s

    def verify(self, public_key: Point, message: bytes, signature: Tuple[Point, int]) -> bool:
        """SM9签名验证"""
        R, s = signature
        # 计算h = H(M || R)
        h = int.from_bytes(sm3_hash(message + str(R.x).encode() + str(R.y).encode()).encode(), 'big')
        # 验证等式 s * P1 = R + h * public_key
        left = scalar_multiply(s, self.P1)
        right = add_points(R, scalar_multiply(h, public_key))
        return left.x == right.x and left.y == right.y

    def key_exchange(self, initiator_key: Point, responder_key: Point) -> bytes:
        """SM9密钥交换协议"""
        # 生成临时随机数
        r1 = int.from_bytes(sm3_hash(b"exchange_random_1").encode(), 'big') % N
        r2 = int.from_bytes(sm3_hash(b"exchange_random_2").encode(), 'big') % N

        # 计算临时公钥
        R1 = scalar_multiply(r1, self.P1)
        R2 = scalar_multiply(r2, self.P1)

        # 计算共享密钥
        K1 = scalar_multiply(r1, responder_key)
        K2 = scalar_multiply(r2, initiator_key)

        # 使用SM3导出会话密钥
        shared_key = sm3_hash(str(K1.x).encode() + str(K2.x).encode())
        return shared_key.encode()

    def encrypt(self, public_key: Point, plaintext: bytes) -> Tuple[Point, bytes]:
        """SM9加密算法"""
        # 生成随机数
        r = int.from_bytes(sm3_hash(b"encryption_random").encode(), 'big') % N
        # 计算C1 = r * P1
        C1 = scalar_multiply(r, self.P1)
        # 计算共享密钥
        k = scalar_multiply(r, public_key)
        # 使用SM4加密明文
        key = sm3_hash(str(k.x).encode())[:16].encode()
        C2 = sm4_crypt_ecb(key, plaintext, 0)
        return C1, C2

    def decrypt(self, private_key: Point, ciphertext: Tuple[Point, bytes]) -> bytes:
        """SM9解密算法"""
        C1, C2 = ciphertext
        # 计算共享密钥
        k = scalar_multiply(private_key.x, C1)
        # 使用SM4解密
        key = sm3_hash(str(k.x).encode())[:16].encode()
        plaintext = sm4_crypt_ecb(key, C2, 1)
        return plaintext


# 测试代码
if __name__ == "__main__":
    # 初始化SM9系统
    sm9 = SM9()

    # 生成主密钥对
    master_private_key, master_public_key = sm9.generate_master_key()
    print("主密钥对生成完成")

    # 为用户生成密钥对
    user_id = "alice@example.com"
    user_private_key, encrypted_key = sm9.generate_user_key(master_private_key, user_id)
    print(f"用户 {user_id} 的密钥对生成完成")

    # 测试签名和验证
    message = b"Hello, SM9!"
    signature = sm9.sign(user_private_key, message)
    is_valid = sm9.verify(master_public_key, message, signature)
    print(f"签名验证结果: {is_valid}")

    # 测试加密和解密
    plaintext = b"Secret message"
    ciphertext = sm9.encrypt(master_public_key, plaintext)
    decrypted = sm9.decrypt(user_private_key, ciphertext)
    print(f"解密结果: {decrypted}")

    # 测试密钥交换
    alice_key = user_private_key
    bob_id = "bob@example.com"
    bob_private_key, _ = sm9.generate_user_key(master_private_key, bob_id)
    shared_key = sm9.key_exchange(alice_key, bob_private_key)
    print(f"共享密钥生成完成: {shared_key.hex()}")
