# SM3密码杂凑算法的Python实现

# IV初始值（常量）
IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
      0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]

# T常量
def T(j):
    if j < 16:
        return 0x79cc4519
    return 0x7a879d8a

# 循环左移函数
def rotl(x, n, w=32):
    n = n % w
    return ((x << n) | (x >> (w - n))) & 0xffffffff

# 布尔函数FF
def FF(x, y, z, j):
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)

# 布尔函数GG
def GG(x, y, z, j):
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (~x & z)

# P0置换函数
def P0(x):
    return x ^ rotl(x, 9) ^ rotl(x, 17)

# P1置换函数
def P1(x):
    return x ^ rotl(x, 15) ^ rotl(x, 23)

# 消息填充函数
def pad_message(message):
    # 将消息转换为二进制
    bin_message = ''.join([bin(x)[2:].zfill(8) for x in message])
    length = len(bin_message)
    
    # 计算需要填充的比特数
    k = (448 - length - 1) % 512
    if k < 0:
        k += 512
    
    # 填充1和k个0
    pad = '1' + '0' * k
    
    # 添加消息长度（64位）
    length_bin = bin(length)[2:].zfill(64)
    
    # 返回填充后的消息
    return bin_message + pad + length_bin

# 消息扩展函数
def message_extension(bin_message):
    W = []
    W_ = []
    
    # 将消息分割为16个字
    for i in range(16):
        W.append(int(bin_message[i*32:(i+1)*32], 2))
    
    # 生成剩余的W值
    for j in range(16, 68):
        temp = P1(W[j-16] ^ W[j-9] ^ rotl(W[j-3], 15)) ^ rotl(W[j-13], 7) ^ W[j-6]
        W.append(temp)
    
    # 生成W'值
    for j in range(64):
        W_.append(W[j] ^ W[j+4])
    
    return W, W_

# 压缩函数
def CF(V, B):
    W, W_ = message_extension(B)
    
    A, B, C, D, E, F, G, H = V
    
    for j in range(64):
        SS1 = rotl((rotl(A, 12) + E + rotl(T(j), j)) & 0xffffffff, 7)
        SS2 = SS1 ^ rotl(A, 12)
        TT1 = (FF(A, B, C, j) + D + SS2 + W_[j]) & 0xffffffff
        TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xffffffff
        D = C
        C = rotl(B, 9)
        B = A
        A = TT1
        H = G
        G = rotl(F, 19)
        F = E
        E = P0(TT2)
    
    return [A^V[0], B^V[1], C^V[2], D^V[3], E^V[4], F^V[5], G^V[6], H^V[7]]

# SM3主函数
def sm3_hash(message):
    # 消息预处理
    padded = pad_message(message)
    
    # 初始化变量
    V = IV.copy()
    
    # 分组处理
    for i in range(0, len(padded), 512):
        B = padded[i:i+512]
        V = CF(V, B)
    
    # 输出结果
    result = ''
    for v in V:
        result += hex(v)[2:].zfill(8)
    return result

# 使用示例
def main():
    # 测试用例
    message = bytes.fromhex("616263") # message = b"abc"
    hash_value = sm3_hash(message)
    print(f"Message: {message}")
    print(f"Hash: {hash_value}")

if __name__ == "__main__":
    main()
