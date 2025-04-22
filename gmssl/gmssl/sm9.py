# 导入所需的标准库和第三方库
import binascii  # 用于二进制和ASCII转换
from math import ceil, floor, log  # 数学计算函数
from gmssl.gmssl.sm3 import sm3_kdf, sm3_hash  # SM3密码杂凑函数和KDF密钥派生函数
from random import SystemRandom  # 密码学安全的随机数生成器
# 导入有限域、椭圆曲线和双线性对运算相关模块
# fq: 实现有限域运算(FQ, FQ2, FQ12)
# ec: 实现椭圆曲线G1和G2群上的点运算
# ate: 实现optimal ate双线性对计算
import gmssl.gmssl.optimized_field_elements as fq
import gmssl.gmssl.optimized_curve as ec
import gmssl.gmssl.optimized_pairing as ate

# 定义操作结果状态常量
FAILURE = False
SUCCESS = True


# 工具函数：计算一个数的比特长度
def bitlen(n):
    """计算一个数的比特长度
    Args:
        n: 输入整数
    Returns:
        比特长度(向下取整的log2(n) + 1)
    """
    return floor(log(n, 2) + 1)


# 工具函数：将整数转换为指定长度的字节串的十六进制表示
def i2sp(m, l):
    """整数到字节串的转换(Integer-to-String Primitive)
    Args:
        m: 待转换的整数
        l: 期望的字节串长度
    Returns:
        固定长度的十六进制字符串
    """
    format_m = ('%x' % m).zfill(l * 2).encode('utf-8')
    octets = [j for j in binascii.a2b_hex(format_m)]
    octets = octets[0:l]
    return ''.join(['%02x' % oc for oc in octets])


# 工具函数：将有限域元素转换为字符串
def fe2sp(fe):
    """有限域元素到字符串的转换(Field Element-to-String Primitive)
    Args:
        fe: 有限域元素(FQ/FQ2/FQ12类型)
    Returns:
        元素系数的16进制字符串表示
    """
    fe_str = ''.join(['%x' % c for c in fe.coeffs])
    if (len(fe_str) % 2) == 1:
        fe_str = '0' + fe_str
    return fe_str


# 工具函数：将椭圆曲线点转换为字符串
def ec2sp(P):
    """椭圆曲线点到字符串的转换(EC Point-to-String Primitive)
    Args:
        P: 椭圆曲线上的点(x,y,z)坐标
    Returns:
        点坐标的16进制字符串表示
    """
    ec_str = ''.join([fe2sp(fe) for fe in P])
    return ec_str


# 工具函数：将字符串转换为十六进制字节列表
def str2hexbytes(str_in):
    """字符串转换为16进制字节列表
    Args:
        str_in: 输入字符串
    Returns:
        字节值列表
    """
    return [b for b in str_in.encode('utf-8')]


# Hash-to-Range函数：将消息映射到指定范围内的整数
def h2rf(i, z, n):
    """哈希到范围函数(Hash-to-Range Function)
    将消息哈希映射到[1,n-1]范围内
    Args:
        i: 函数标识符
        z: 输入消息
        n: 上界(通常为群的阶)
    Returns:
        范围在[1,n-1]内的整数
    """
    l = 8 * ceil((5 * bitlen(n)) / 32)  # 计算所需比特长度
    msg = i2sp(i, 1).encode('utf-8')  # 编码函数标识符
    ha = sm3_kdf(msg + z, l)  # 使用SM3-KDF进行哈希
    h = int(ha, 16)  # 转换为整数
    return (h % (n - 1)) + 1  # 映射到指定范围


# 系统设置函数：生成主密钥对
def setup(scheme):
    """系统主密钥对生成函数
    Args:
        scheme: 方案类型('sign'/'keyagreement'/'encrypt')
    Returns:
        (master_public_key, master_secret_key):
        - master_public_key: (P1,P2,Ppub,g)元组
          P1: G2群生成元
          P2: G1群生成元
          Ppub: 主公钥点
          g: 双线性对值
        - master_secret_key: 主私钥s
    """
    P1 = ec.G2  # G2群生成元
    P2 = ec.G1  # G1群生成元
    # 使用密码学安全的随机数生成器
    rand_gen = SystemRandom()
    # 随机生成主私钥s
    s = rand_gen.randrange(ec.curve_order)
    # 根据不同方案计算主公钥和系统参数:
    # 签名方案: Ppub = sP2, g = e(P1,Ppub)
    # 密钥交换/加密方案: Ppub = sP1, g = e(Ppub,P2)
    if (scheme == 'sign'):
        Ppub = ec.multiply(P2, s)
        g = ate.pairing(P1, Ppub)
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):
        Ppub = ec.multiply(P1, s)
        g = ate.pairing(Ppub, P2)
    else:
        raise Exception('Invalid scheme')
    master_public_key = (P1, P2, Ppub, g)
    return (master_public_key, s)


# 用户私钥生成函数
def private_key_extract(scheme, master_public, master_secret, identity):
    """用户私钥生成函数
    Args:
        scheme: 方案类型
        master_public: 主公钥(P1,P2,Ppub,g)
        master_secret: 主私钥s
        identity: 用户身份标识符
    Returns:
        用户私钥Da，失败返回FAILURE
    """
    P1 = master_public[0]  # G2群生成元
    P2 = master_public[1]  # G1群生成元
    # 计算用户身份哈希值
    user_id = sm3_hash(str2hexbytes(identity))
    # 计算h1 = H1(ID||hid)，hid = 0x01
    m = h2rf(1, (user_id + '01').encode('utf-8'), ec.curve_order)
    m = master_secret + m
    # 检查t是否为0模n
    if (m % ec.curve_order) == 0:
        return FAILURE
    # 计算私钥 Da = s/(s+h1)·P
    m = master_secret * fq.prime_field_inv(m, ec.curve_order)
    # 根据方案类型选择基点:
    # 签名方案: Da = (s/(s+h1))P1
    # 密钥交换/加密方案: Da = (s/(s+h1))P2
    if (scheme == 'sign'):
        Da = ec.multiply(P1, m)
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):
        Da = ec.multiply(P2, m)
    else:
        raise Exception('Invalid scheme')
    return Da


def public_key_extract(scheme, master_public, identity):
    """用户公钥生成函数
    Args:
        scheme: 方案类型
        master_public: 主公钥(P1,P2,Ppub,g)
        identity: 用户身份标识符
    Returns:
        用户公钥点Q = H1(ID||hid)·P + Ppub
    """
    P1, P2, Ppub, g = master_public
    # 计算用户身份哈希值
    user_id = sm3_hash(str2hexbytes(identity))
    # 计算h1 = H1(ID||hid)，hid = 0x01
    h1 = h2rf(1, (user_id + '01').encode('utf-8'), ec.curve_order)
    # 根据方案类型选择基点计算 H1(ID||hid)·P
    if (scheme == 'sign'):
        Q = ec.multiply(P2, h1)  # Q = h1·P2
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):
        Q = ec.multiply(P1, h1)  # Q = h1·P1
    else:
        raise Exception('Invalid scheme')
    # 计算公钥 Q = H1(ID||hid)·P + Ppub
    Q = ec.add(Q, Ppub)
    return Q


def sign(master_public, Da, msg):
    """SM9签名生成函数
    Args:
        master_public: 主公钥(P1,P2,Ppub,g)
        Da: 签名者私钥
        msg: 待签名消息
    Returns:
        签名值(h,S)，其中:
        - h: 消息哈希值
        - S: 椭圆曲线点
    """
    g = master_public[3]  # 获取双线性对值g
    # 随机选择整数x
    rand_gen = SystemRandom()
    x = rand_gen.randrange(ec.curve_order)
    # 计算w = g^x
    w = g ** x
    # 计算h = H2(M||w)
    msg_hash = sm3_hash(str2hexbytes(msg))
    z = (msg_hash + fe2sp(w)).encode('utf-8')
    h = h2rf(2, z, ec.curve_order)
    # 计算l = x - h mod n
    l = (x - h) % ec.curve_order
    # 计算签名S = l·Da
    S = ec.multiply(Da, l)
    return (h, S)


def verify(master_public, identity, msg, signature):
    """SM9签名验证函数
    Args:
        master_public: 主公钥(P1,P2,Ppub,g)
        identity: 签名者身份
        msg: 已签名消息
        signature: 签名值(h,S)
    Returns:
        验证结果: SUCCESS或FAILURE
    """
    (h, S) = signature
    # 验证h是否在正确范围内
    if (h < 0) | (h >= ec.curve_order):
        return FAILURE
    # 验证S是否为G2群上的有效点
    if ec.is_on_curve(S, ec.b2) == False:
        return FAILURE
    # 计算签名者公钥Q
    Q = public_key_extract('sign', master_public, identity)
    g = master_public[3]
    # 计算u = e(S,Q)
    u = ate.pairing(S, Q)
    # 计算t = g^h
    t = g ** h
    # 计算w' = u·t
    wprime = u * t
    # 计算h' = H2(M||w')
    msg_hash = sm3_hash(str2hexbytes(msg))
    z = (msg_hash + fe2sp(wprime)).encode('utf-8')
    h2 = h2rf(2, z, ec.curve_order)
    # 验证h == h'
    if h != h2:
        return FAILURE
    return SUCCESS


def generate_ephemeral(master_public, identity):
    """生成密钥协商的临时密钥对
    Args:
        master_public: 主公钥
        identity: 用户身份
    Returns:
        (私钥x, 公钥R = x·Q)元组
    """
    # 计算用户公钥Q
    Q = public_key_extract('keyagreement', master_public, identity)
    # 随机生成临时私钥x
    rand_gen = SystemRandom()
    x = rand_gen.randrange(ec.curve_order)
    # 计算临时公钥R = x·Q
    R = ec.multiply(Q, x)
    return (x, R)


def generate_session_key(idA, idB, Ra, Rb, D, x, master_public, entity, l):
    """生成会话密钥
    Args:
        idA: A的身份
        idB: B的身份
        Ra: A的临时公钥
        Rb: B的临时公钥
        D: 本方的私钥
        x: 本方的临时私钥
        master_public: 主公钥
        entity: 调用方身份('A'或'B')
        l: 期望的密钥长度(比特)
    Returns:
        会话密钥SK
    """
    P1, P2, Ppub, g = master_public
    # 根据调用方选择对方的临时公钥
    if entity == 'A':
        R = Rb
    elif entity == 'B':
        R = Ra
    else:
        raise Exception('Invalid entity')
    # 计算g1 = e(R,D)
    g1 = ate.pairing(R, D)
    # 计算g2 = g^x
    g2 = g ** x
    # 计算g3 = g1^x
    g3 = g1 ** x
    # B方交换g1和g2的顺序
    if (entity == 'B'):
        (g1, g2) = (g2, g1)
    # 计算双方身份的哈希值
    uidA = sm3_hash(str2hexbytes(idA))
    uidB = sm3_hash(str2hexbytes(idB))
    # 构造KDF输入
    kdf_input = uidA + uidB
    kdf_input += ec2sp(Ra) + ec2sp(Rb)
    kdf_input += fe2sp(g1) + fe2sp(g2) + fe2sp(g3)
    # 使用KDF导出会话密钥
    sk = sm3_kdf(kdf_input.encode('utf-8'), l)
    return sk


def kem_encap(master_public, identity, l):
    """密钥封装函数(Key Encapsulation Mechanism)
    将随机生成的会话密钥k封装为密文C1

    Args:
        master_public: 主公钥(P1,P2,Ppub,g)
        identity: 接收方身份
        l: 期望的密钥长度(比特)
    Returns:
        (k, C1)元组:
        - k: 会话密钥
        - C1: 密文点(封装的密钥)
    """
    P1, P2, Ppub, g = master_public
    # 计算接收方公钥Q
    Q = public_key_extract('encrypt', master_public, identity)
    # 随机选择整数x
    rand_gen = SystemRandom()
    x = rand_gen.randrange(ec.curve_order)
    # 计算C1 = x·Q
    C1 = ec.multiply(Q, x)
    # 计算t = g^x
    t = g ** x
    # 计算接收方身份哈希值
    uid = sm3_hash(str2hexbytes(identity))
    # 构造KDF输入数据
    kdf_input = ec2sp(C1) + fe2sp(t) + uid
    # 使用KDF导出会话密钥k
    k = sm3_kdf(kdf_input.encode('utf-8'), l)
    return (k, C1)


def kem_decap(master_public, identity, D, C1, l):
    """密钥解封装函数
    使用私钥D解封装密文C1得到会话密钥k

    Args:
        master_public: 主公钥
        identity: 接收方身份
        D: 接收方私钥
        C1: 密文点
        l: 密钥长度(比特)
    Returns:
        解封装得到的会话密钥k，失败返回FAILURE
    """
    # 验证C1是否为G2群上的有效点
    if ec.is_on_curve(C1, ec.b2) == False:
        return FAILURE
    # 计算t = e(C1,D)
    t = ate.pairing(C1, D)
    # 计算接收方身份哈希值
    uid = sm3_hash(str2hexbytes(identity))
    # 构造KDF输入数据
    kdf_input = ec2sp(C1) + fe2sp(t) + uid
    # 使用KDF导出会话密钥k
    k = sm3_kdf(kdf_input.encode('utf-8'), l)

    return k


def kem_dem_enc(master_public, identity, message, v):
    """SM9加密函数(KEM-DEM方式)
    使用KEM-DEM(密钥封装机制-数据加密机制)方式加密消息

    Args:
        master_public: 主公钥
        identity: 接收方身份
        message: 待加密消息
        v: MAC标签长度(比特)
    Returns:
        (C1,C2,C3)密文元组:
        - C1: 封装的密钥
        - C2: 加密的消息
        - C3: MAC标签
    """
    # 将消息转换为字节序列
    hex_msg = str2hexbytes(message)
    mbytes = len(hex_msg)  # 消息字节长度
    mbits = mbytes * 8  # 消息比特长度
    # 使用KEM生成并封装会话密钥
    k, C1 = kem_encap(master_public, identity, mbits + v)
    k = str2hexbytes(k)
    # 将会话密钥k分为加密密钥k1和认证密钥k2
    k1 = k[:mbytes]  # 用于加密消息
    k2 = k[mbytes:]  # 用于生成MAC
    # 使用k1对消息进行异或加密得到C2
    C2 = []
    for i in range(mbytes):
        C2.append(hex_msg[i] ^ k1[i])
    # 使用k2生成MAC标签C3
    hash_input = C2 + k2
    C3 = sm3_hash(hash_input)[:int(v / 8)]

    return (C1, C2, C3)


def kem_dem_dec(master_public, identity, D, ct, v):
    """SM9解密函数
    解密KEM-DEM方式加密的密文

    Args:
        master_public: 主公钥
        identity: 接收方身份
        D: 接收方私钥
        ct: (C1,C2,C3)密文元组
        v: MAC标签长度(比特)
    Returns:
        解密得到的明文消息，失败返回FAILURE
    """
    C1, C2, C3 = ct
    # 获取密文长度
    mbytes = len(C2)
    l = mbytes * 8 + v
    # 使用KEM解封装得到会话密钥k
    k = kem_decap(master_public, identity, D, C1, l)
    # 将会话密钥k分为加密密钥k1和认证密钥k2
    k = str2hexbytes(k)
    k1 = k[:mbytes]
    k2 = k[mbytes:]
    # 验证MAC标签
    hash_input = C2 + k2
    C3prime = sm3_hash(hash_input)[:int(v / 8)]
    if C3 != C3prime:
        return FAILURE
    # 使用k1对C2进行异或解密
    pt = []
    for i in range(mbytes):
        pt.append(chr(C2[i] ^ k1[i]))
    # 将解密结果转换为字符串
    message = ''.join(pt)

    return message
