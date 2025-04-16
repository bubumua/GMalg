import random
from math import ceil
import sm3.sm3 as sm3


class SM2:
    def __init__(self):
        """
        初始化SM2椭圆曲线参数, e.g. Fp-256。256 是指16进制计算位数
        """
        # self.p = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
        # self.a = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16)
        # self.b = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)
        # self.n = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)
        # self.Gx = int('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', 16)
        # self.Gy = int('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', 16)
        self.p = int('8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3', 16)
        self.a = int('787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498', 16)
        self.b = int('63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A', 16)
        self.Gx = int('421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D', 16)
        self.Gy = int('0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2', 16)
        self.n = int('8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7', 16)
        self.h = int('1', 16)  # cofactor

    def generate_keypair(self):
        """生成SM2密钥对"""
        private_key = random.randint(1, self.n - 1)
        public_key = self.scalar_mult(private_key, self.Gx, self.Gy)
        return private_key, public_key

    def point_add(self, P1x, P1y, P2x, P2y):
        """
        椭圆曲线点加法
        """
        if P1x == P2x and P1y == P2y:
            lam = (3 * P1x * P1x + self.a) * pow(2 * P1y, -1, self.p) % self.p
        else:
            lam = (P2y - P1y) * pow(P2x - P1x, -1, self.p) % self.p

        x3 = (lam * lam - P1x - P2x) % self.p
        y3 = (lam * (P1x - x3) - P1y) % self.p
        return x3, y3

    def scalar_mult(self, k, Px, Py):
        """
        使用双倍加算法计算倍点
        """
        Qx, Qy = 0, 0
        k_bin = bin(k)[2:]

        for bit in k_bin:
            # Point doubling
            if Qx != 0 or Qy != 0:
                Qx, Qy = self.point_add(Qx, Qy, Qx, Qy)
            # Point addition
            if bit == '1':
                if Qx == 0 and Qy == 0:
                    Qx, Qy = Px, Py
                else:
                    Qx, Qy = self.point_add(Qx, Qy, Px, Py)
        return Qx, Qy

    def kdf(self, z, klen):
        """
        调用SM3的密钥派生函数
        """
        v = ceil(klen / 256)
        ha = []
        for i in range(v):
            ha.append(sm3.sm3_hash(list(bytes.fromhex(z + '{:08x}'.format(i + 1))), print_log=False))

        if klen % 256 != 0:
            ha[-1] = ha[-1][:klen - (v - 1) * 256]
        return ''.join(ha)

    def sign(self, message, private_key, user_id="1234567812345678"):
        """
        SM2签名算法
        message: 待签名消息
        private_key: 私钥
        user_id: 用户ID
        """
        # 1. 计算ZA
        ENTLA = '{:04x}'.format(len(user_id) * 8)
        user_id_hex = user_id.encode().hex()
        a_hex = '{:064x}'.format(self.a)
        b_hex = '{:064x}'.format(self.b)
        gx_hex = '{:064x}'.format(self.Gx)
        gy_hex = '{:064x}'.format(self.Gy)

        public_key = self.scalar_mult(private_key, self.Gx, self.Gy)
        px_hex = '{:064x}'.format(public_key[0])
        py_hex = '{:064x}'.format(public_key[1])

        Z = ENTLA + user_id_hex + a_hex + b_hex + gx_hex + gy_hex + px_hex + py_hex
        ZA = sm3.sm3_hash(bytes.fromhex(Z), print_log=False)

        # 2. 计算消息哈希值
        M = ZA + message.encode().hex()
        e = sm3.sm3_hash(bytes.fromhex(M), print_log=False)
        e_int = int(e, 16)

        while True:
            # 3. 生成随机数k
            k = random.randint(1, self.n - 1)

            # 4. 计算点(x1, y1) = kG
            x1, y1 = self.scalar_mult(k, self.Gx, self.Gy)

            # 5. 计算r = (e + x1) mod n
            r = (e_int + x1) % self.n
            if r == 0 or r + k == self.n:
                continue

            # 6. 计算s = ((1 + private_key)^(-1) * (k - r * private_key)) mod n
            s = (pow(1 + private_key, -1, self.n) * (k - r * private_key)) % self.n
            if s == 0:
                continue

            return r, s

    def verify(self, message, signature, public_key, user_id="1234567812345678"):
        """
        SM2签名验证
        message: 消息
        signature: (r,s)签名值
        public_key: 公钥点坐标(x,y)
        """
        r, s = signature

        # 1. 验证r,s是否在[1,n-1]范围内
        if r < 1 or r > self.n - 1 or s < 1 or s > self.n - 1:
            return False

        # 2. 计算ZA
        ENTLA = '{:04x}'.format(len(user_id) * 8)
        user_id_hex = user_id.encode().hex()
        a_hex = '{:064x}'.format(self.a)
        b_hex = '{:064x}'.format(self.b)
        gx_hex = '{:064x}'.format(self.Gx)
        gy_hex = '{:064x}'.format(self.Gy)
        px_hex = '{:064x}'.format(public_key[0])
        py_hex = '{:064x}'.format(public_key[1])

        Z = ENTLA + user_id_hex + a_hex + b_hex + gx_hex + gy_hex + px_hex + py_hex
        ZA = sm3.sm3_hash(bytes.fromhex(Z), print_log=False)

        # 3. 计算e值
        M = ZA + message.encode().hex()
        e = int(sm3.sm3_hash(bytes.fromhex(M), print_log=False), 16)

        # 4. 计算t = (r + s) mod n
        t = (r + s) % self.n
        if t == 0:
            return False

        # 5. 计算(x1', y1') = sG + tP
        sg_x, sg_y = self.scalar_mult(s, self.Gx, self.Gy)
        tP_x, tP_y = self.scalar_mult(t, public_key[0], public_key[1])
        x1, y1 = self.point_add(sg_x, sg_y, tP_x, tP_y)

        # 6. 计算R = (e + x1') mod n
        R = (e + x1) % self.n

        # 7. 验证R == r
        return R == r

    def key_exchange_init_A(self, id_a, id_b, private_key_a):
        """
        A方发起密钥交换
        输入:A的ID、B的ID、A的私钥
        输出:发送给B的数据(R_A)
        """
        # 1. 产生随机数r_A
        r_a = random.randint(1, self.n - 1)

        # 2. 计算R_A = r_A * G
        ra_x, ra_y = self.scalar_mult(r_a, self.Gx, self.Gy)

        # 3. 生成并保存临时数据
        self.id_a = id_a
        self.id_b = id_b
        self.r_a = r_a
        self.private_key_a = private_key_a

        return ra_x, ra_y

    def key_exchange_init_B(self, id_a, id_b, private_key_b, ra_x, ra_y):
        """
        B方响应A的密钥交换请求
        输入:A的ID、B的ID、B的私钥、A方发来的R_A
        输出:发送给A的数据(R_B)和计算出的共享密钥K
        """
        # 1. 产生随机数r_B
        r_b = random.randint(1, self.n - 1)

        # 2. 计算R_B = r_B * G
        rb_x, rb_y = self.scalar_mult(r_b, self.Gx, self.Gy)

        # 3. 计算共享密钥
        # 计算V = h * t_B * (R_A + P_A)
        v_x, v_y = self.scalar_mult(r_b, ra_x, ra_y)

        # 使用KDF生成共享密钥
        x2_hex = '{:064x}'.format(v_x)
        y2_hex = '{:064x}'.format(v_y)
        shared_key = self.kdf(x2_hex + y2_hex, 128)

        return rb_x, rb_y, shared_key

    def key_exchange_finish_A(self, rb_x, rb_y):
        """
        A方完成密钥交换
        输入:B方发来的R_B
        输出:计算出的共享密钥K
        """
        # 计算共享密钥
        # 计算U = h * t_A * (R_B + P_B)
        v_x, v_y = self.scalar_mult(self.r_a, rb_x, rb_y)

        # 使用KDF生成共享密钥
        x2_hex = '{:064x}'.format(v_x)
        y2_hex = '{:064x}'.format(v_y)
        shared_key = self.kdf(x2_hex + y2_hex, 128)

        return shared_key

    def encrypt(self, message, public_key):
        """
        SM2 加密
        """
        # Generate random key k
        k = random.randint(1, self.n - 1)

        # Calculate public key point
        Px, Py = self.scalar_mult(k, self.Gx, self.Gy)

        # Convert message to bytes and hex
        msg_bytes = message.encode()
        msg_hex = msg_bytes.hex()

        # Calculate shared point
        x2, y2 = self.scalar_mult(k, public_key[0], public_key[1])
        x2_hex = '{:064x}'.format(x2)
        y2_hex = '{:064x}'.format(y2)

        # Generate key using KDF
        t = self.kdf(x2_hex + y2_hex, len(msg_bytes) * 8)

        # XOR encryption
        C2 = '{:x}'.format(int(msg_hex, 16) ^ int(t, 16))

        # Calculate hash
        C3 = sm3.sm3_hash(list(bytes.fromhex(x2_hex + msg_hex + y2_hex)), print_log=False)

        return (Px, Py), C2, C3

    def decrypt(self, cipher, private_key):
        """
        SM2 解密
        """
        C1, C2, C3 = cipher

        # Calculate shared point using private key
        x2, y2 = self.scalar_mult(private_key, C1[0], C1[1])
        x2_hex = '{:064x}'.format(x2)
        y2_hex = '{:064x}'.format(y2)

        # Generate key using KDF
        klen = len(C2) * 4
        t = self.kdf(x2_hex + y2_hex, klen)

        # XOR decryption
        msg_hex = '{:x}'.format(int(C2, 16) ^ int(t, 16))

        # Verify hash
        hash_verify = sm3.sm3_hash(list(bytes.fromhex(x2_hex + msg_hex + y2_hex)), print_log=False)
        if hash_verify != C3:
            raise Exception("Decryption failed: Hash verification error")

        # Convert hex to message
        msg = bytes.fromhex(msg_hex).decode()
        return msg


if __name__ == "__main__":
    sm2 = SM2()
    # 生成密钥对
    private_key, public_key = sm2.generate_keypair()
    # 以16进制字符串形式打印私钥和公钥
    private_key_hex = '{:x}'.format(private_key)
    public_key_hex = '{:048x},{:048x}'.format(public_key[0], public_key[1])
    print("Private key:", private_key_hex)
    print("Public key:", public_key_hex)
    # 定义明文消息
    message = "Hello, SM2!"
    print("Message:", message)

    # 签名消息
    signature = sm2.sign(message, private_key)
    signature_hex = '{:048x},{:048x}'.format(signature[0], signature[1])
    print("Signature:", signature_hex)
    # 验证签名
    is_valid = sm2.verify(message, signature, public_key)
    print("Signature valid:", is_valid)
    # 修改消息进行验证
    modified_message = "Hello, SM2! Modified"
    modified_message_hex = '{:048x}'.format(int(modified_message.encode().hex(), 16))
    print("Modified message:", modified_message)
    is_valid = sm2.verify(modified_message, signature, public_key)
    print("Signature valid:", is_valid)

    print("====Shared key exchanging====")
    # A方发起密钥交换
    id_a = "ALICE"
    id_b = "BOB"
    private_key_a = random.randint(1, sm2.n - 1)
    ra_x, ra_y = sm2.key_exchange_init_A(id_a, id_b, private_key_a)
    # B方响应并生成共享密钥
    private_key_b = random.randint(1, sm2.n - 1)
    rb_x, rb_y, key_b = sm2.key_exchange_init_B(id_a, id_b, private_key_b, ra_x, ra_y)
    # A方完成交换并生成相同的共享密钥
    key_a = sm2.key_exchange_finish_A(rb_x, rb_y)
    # 验证双方生成的密钥相同
    print("Key A:", key_a)
    print("Key B:", key_b)
    same_shared_key = key_a == key_b
    print(f"Shared key exchange {"successful" if same_shared_key else "failed"}!")

    print("====cryption/decryption====")
    # 生成加密密文
    cipher = sm2.encrypt(message, public_key)
    print("Ciphertext:", cipher)
    # 解密密文
    decrypted_message = sm2.decrypt(cipher, private_key)
    print("Decrypted message:", decrypted_message)
    print("====cryption/decryption done====")

    # 验证倍点运算正确性
    # 定义测试点（使用椭圆曲线的基点 G）
    Px, Py = sm2.Gx, sm2.Gy

    # 定义标量 k
    k = 10

    # 计算标量乘法 kP
    Qx, Qy = sm2.scalar_mult(k, Px, Py)

    # 验证结果是否在椭圆曲线上
    # 椭圆曲线方程: y^2 = x^3 + ax + b (mod p)
    assert (Qy ** 2 - (Qx ** 3 + sm2.a * Qx + sm2.b)) % sm2.p == 0, "Resulting point is not on the curve"

    # 验证特殊情况: k = 1 应返回原点
    Qx1, Qy1 = sm2.scalar_mult(1, Px, Py)
    assert Qx1 == Px and Qy1 == Py, "k=1 test failed"

    # 验证特殊情况: k = 0 应返回无穷远点 (这里用 (0, 0) 表示)
    Qx0, Qy0 = sm2.scalar_mult(0, Px, Py)
    assert Qx0 == 0 and Qy0 == 0, "k=0 test failed"

    print("All tests passed!")
