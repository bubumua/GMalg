# SM4 分组算法实现
# 参考: GM/T 32907-2016 SM4分组加密算法

# S盒
SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
]

# 系统参数FK
FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

# 固定参数CK
CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
]


def rotl(x, n):
    """循环左移n位"""
    return ((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)


def get_uint32_be(key_data):
    """字节串转换成uint32"""
    return int.from_bytes(key_data, byteorder='big', signed=False)


def put_uint32_be(n):
    """uint32转换成字节串"""
    return int.to_bytes(n, length=4, byteorder='big', signed=False)


def str_to_bytes(hex_str):
    """将16进制字符串转换为字节串"""
    return bytes.fromhex(hex_str)


def bytes_to_str(byte_array):
    """将字节串转换为16进制字符串"""
    return ''.join(['{:02x}'.format(b) for b in byte_array])


def sm4_T(wa):
    """SM4 合成置换 T=L(tau(·))"""
    a = wa
    wb = 0

    # 输入字的第1、2、3、4字节分别经过S盒替换，然后合并
    b0 = SBOX[(a >> 24) & 0xff]
    wb |= b0 << 24
    b1 = SBOX[(a >> 16) & 0xff]
    wb |= b1 << 16
    b2 = SBOX[(a >> 8) & 0xff]
    wb |= b2 << 8
    b3 = SBOX[a & 0xff]
    wb |= b3
    # 线性变换L
    c = wb ^ (rotl(wb, 2)) ^ (rotl(wb, 10)) ^ (rotl(wb, 18)) ^ (rotl(wb, 24))
    return c


def sm4_keyexpension_T(wa):
    """SM4 密钥扩展合成置换 T'=L'(tau(·))"""
    a = wa
    wb = 0

    # 输入字的第1、2、3、4字节分别经过S盒替换，然后合并
    b0 = SBOX[(a >> 24) & 0xff]
    wb |= b0 << 24
    b1 = SBOX[(a >> 16) & 0xff]
    wb |= b1 << 16
    b2 = SBOX[(a >> 8) & 0xff]
    wb |= b2 << 8
    b3 = SBOX[a & 0xff]
    wb |= b3
    # 线性变换L'
    c = wb ^ (rotl(wb, 13)) ^ (rotl(wb, 23))
    return c


def sm4_f(x0, x1, x2, x3, rk):
    """轮函数F"""
    return x0 ^ sm4_T(x1 ^ x2 ^ x3 ^ rk)


def sm4_keyexpension_f(k0, k1, k2, k3, ck):
    """密钥扩展轮函数F'"""
    return k0 ^ sm4_keyexpension_T(k1 ^ k2 ^ k3 ^ ck)


def sm4_set_key(mk, mode):
    """密钥扩展算法,生成轮密钥"""
    MK = []
    k = []
    rk = []

    # 将密钥转换为4个字
    MK.append(get_uint32_be(mk[0:4]))
    MK.append(get_uint32_be(mk[4:8]))
    MK.append(get_uint32_be(mk[8:12]))
    MK.append(get_uint32_be(mk[12:16]))

    # 与系统参数FK异或
    k.append(MK[0] ^ FK[0])
    k.append(MK[1] ^ FK[1])
    k.append(MK[2] ^ FK[2])
    k.append(MK[3] ^ FK[3])

    # 生成32个轮密钥
    for i in range(32):
        k.append(sm4_keyexpension_f(k[i], k[i + 1], k[i + 2], k[i + 3], CK[i]))
        rk.append(k[i + 4])
    # rk_print = [bytes_to_str(put_uint32_be(i)) for i in rk]
    # print(f"rk[]: {rk_print}")

    if mode == 0:  # 加密
        return rk
    else:  # 解密
        for i in range(16):
            t = rk[i]
            rk[i] = rk[31 - i]
            rk[31 - i] = t
        return rk


def sm4_one_round(sk, in_put, out_put):
    """加解密一个分组"""
    ulbuf = []

    ulbuf.append(get_uint32_be(in_put[0:4]))
    ulbuf.append(get_uint32_be(in_put[4:8]))
    ulbuf.append(get_uint32_be(in_put[8:12]))
    ulbuf.append(get_uint32_be(in_put[12:16]))

    for i in range(32):
        ulbuf.append(sm4_f(ulbuf[i], ulbuf[i + 1], ulbuf[i + 2], ulbuf[i + 3], sk[i]))

    out_put[0:4] = put_uint32_be(ulbuf[35])
    out_put[4:8] = put_uint32_be(ulbuf[34])
    out_put[8:12] = put_uint32_be(ulbuf[33])
    out_put[12:16] = put_uint32_be(ulbuf[32])

    # ulbuf_print = [bytes_to_str(put_uint32_be(i)) for i in ulbuf]
    # print(f"X[]: {ulbuf_print}")


def sm4_crypt_ecb(key, input_data, mode):
    """ECB模式加解密"""
    # 检查输入数据长度，必须是16字节的倍数
    length = len(input_data)
    if length % 16:
        raise ValueError("Data length must be a multiple of 16 bytes")

    output_data = bytearray(length)

    # 生成轮密钥
    sk = sm4_set_key(key, mode)

    # 分组处理
    for i in range(0, length, 16):
        input_block = input_data[i:i + 16]
        output_block = bytearray(16)
        sm4_one_round(sk, input_block, output_block)
        output_data[i:i + 16] = output_block

    return output_data


# 测试用例
if __name__ == '__main__':
    # 测试向量
    key = str_to_bytes('0123456789abcdeffedcba9876543210')
    plain = str_to_bytes('0123456789abcdeffedcba9876543210')

    # 加密
    cipher = sm4_crypt_ecb(key, plain, 0)
    print("密文:", bytes_to_str(cipher))

    # 解密
    decrypted = sm4_crypt_ecb(key, cipher, 1)
    print("解密后:", bytes_to_str(decrypted))

    # 重复加密1000000次后的密文
    for _ in range(1000000 - 1):
        cipher = sm4_crypt_ecb(key, cipher, 0)

    print("密文:", bytes_to_str(cipher))
