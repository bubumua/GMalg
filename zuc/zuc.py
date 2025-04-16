# -*- coding: utf-8 -*-
"""
ZUC 序列密码算法的封装实现

该模块实现了 ZUC 算法中的关键部分，包括：
    1. S盒（S0、S1）和常量 D
    2. 比特重组函数、非线性函数 F 以及线性变换 L1 和 L2
    3. 线性反馈移位寄存器（LFSR）的初始化模式和工作模式
    4. 密钥流生成过程

所有变量和函数均添加了详细的注释说明，便于理解代码的实现细节。
"""

# 定义 S盒 S0 和 S1
S0 = [
    [0x3e, 0x72, 0x5b, 0x47, 0xca, 0xe0, 0x00, 0x33, 0x04, 0xd1, 0x54, 0x98, 0x09, 0xb9, 0x6d, 0xcb],
    [0x7b, 0x1b, 0xf9, 0x32, 0xaf, 0x9d, 0x6a, 0xa5, 0xb8, 0x2d, 0xfc, 0x1d, 0x08, 0x53, 0x03, 0x90],
    [0x4d, 0x4e, 0x84, 0x99, 0xe4, 0xce, 0xd9, 0x91, 0xdd, 0xb6, 0x85, 0x48, 0x8b, 0x29, 0x6e, 0xac],
    [0xcd, 0xc1, 0xf8, 0x1e, 0x73, 0x43, 0x69, 0xc6, 0xb5, 0xbd, 0xfd, 0x39, 0x63, 0x20, 0xd4, 0x38],
    [0x76, 0x7d, 0xb2, 0xa7, 0xcf, 0xed, 0x57, 0xc5, 0xf3, 0x2c, 0xbb, 0x14, 0x21, 0x06, 0x55, 0x9b],
    [0xe3, 0xef, 0x5e, 0x31, 0x4f, 0x7f, 0x5a, 0xa4, 0x0d, 0x82, 0x51, 0x49, 0x5f, 0xba, 0x58, 0x1c],
    [0x4a, 0x16, 0xd5, 0x17, 0xa8, 0x92, 0x24, 0x1f, 0x8c, 0xff, 0xd8, 0xae, 0x2e, 0x01, 0xd3, 0xad],
    [0x3b, 0x4b, 0xda, 0x46, 0xeb, 0xc9, 0xde, 0x9a, 0x8f, 0x87, 0xd7, 0x3a, 0x80, 0x6f, 0x2f, 0xc8],
    [0xb1, 0xb4, 0x37, 0xf7, 0x0a, 0x22, 0x13, 0x28, 0x7c, 0xcc, 0x3c, 0x89, 0xc7, 0xc3, 0x96, 0x56],
    [0x07, 0xbf, 0x7e, 0xf0, 0x0b, 0x2b, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xa6, 0x4c, 0x10, 0xfe],
    [0xbc, 0x26, 0x95, 0x88, 0x8a, 0xb0, 0xa3, 0xfb, 0xc0, 0x18, 0x94, 0xf2, 0xe1, 0xe5, 0xe9, 0x5d],
    [0xd0, 0xdc, 0x11, 0x66, 0x64, 0x5c, 0xec, 0x59, 0x42, 0x75, 0x12, 0xf5, 0x74, 0x9c, 0xaa, 0x23],
    [0x0e, 0x86, 0xab, 0xbe, 0x2a, 0x02, 0xe7, 0x67, 0xe6, 0x44, 0xa2, 0x6c, 0xc2, 0x93, 0x9f, 0xf1],
    [0xf6, 0xfa, 0x36, 0xd2, 0x50, 0x68, 0x9e, 0x62, 0x71, 0x15, 0x3d, 0xd6, 0x40, 0xc4, 0xe2, 0x0f],
    [0x8e, 0x83, 0x77, 0x6b, 0x25, 0x05, 0x3f, 0x0c, 0x30, 0xea, 0x70, 0xb7, 0xa1, 0xe8, 0xa9, 0x65],
    [0x8d, 0x27, 0x1a, 0xdb, 0x81, 0xb3, 0xa0, 0xf4, 0x45, 0x7a, 0x19, 0xdf, 0xee, 0x78, 0x34, 0x60]
]

S1 = [
    [0x55, 0xc2, 0x63, 0x71, 0x3b, 0xc8, 0x47, 0x86, 0x9f, 0x3c, 0xda, 0x5b, 0x29, 0xaa, 0xfd, 0x77],
    [0x8c, 0xc5, 0x94, 0x0c, 0xa6, 0x1a, 0x13, 0x00, 0xe3, 0xa8, 0x16, 0x72, 0x40, 0xf9, 0xf8, 0x42],
    [0x44, 0x26, 0x68, 0x96, 0x81, 0xd9, 0x45, 0x3e, 0x10, 0x76, 0xc6, 0xa7, 0x8b, 0x39, 0x43, 0xe1],
    [0x3a, 0xb5, 0x56, 0x2a, 0xc0, 0x6d, 0xb3, 0x05, 0x22, 0x66, 0xbf, 0xdc, 0x0b, 0xfa, 0x62, 0x48],
    [0xdd, 0x20, 0x11, 0x06, 0x36, 0xc9, 0xc1, 0xcf, 0xf6, 0x27, 0x52, 0xbb, 0x69, 0xf5, 0xd4, 0x87],
    [0x7f, 0x84, 0x4c, 0xd2, 0x9c, 0x57, 0xa4, 0xbc, 0x4f, 0x9a, 0xdf, 0xfe, 0xd6, 0x8d, 0x7a, 0xeb],
    [0x2b, 0x53, 0xd8, 0x5c, 0xa1, 0x14, 0x17, 0xfb, 0x23, 0xd5, 0x7d, 0x30, 0x67, 0x73, 0x08, 0x09],
    [0xee, 0xb7, 0x70, 0x3f, 0x61, 0xb2, 0x19, 0x8e, 0x4e, 0xe5, 0x4b, 0x93, 0x8f, 0x5d, 0xdb, 0xa9],
    [0xad, 0xf1, 0xae, 0x2e, 0xcb, 0x0d, 0xfc, 0xf4, 0x2d, 0x46, 0x6e, 0x1d, 0x97, 0xe8, 0xd1, 0xe9],
    [0x4d, 0x37, 0xa5, 0x75, 0x5e, 0x83, 0x9e, 0xab, 0x82, 0x9d, 0xb9, 0x1c, 0xe0, 0xcd, 0x49, 0x89],
    [0x01, 0xb6, 0xbd, 0x58, 0x24, 0xa2, 0x5f, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xb8, 0x95, 0xe4],
    [0xd0, 0x91, 0xc7, 0xce, 0xed, 0x0f, 0xb4, 0x6f, 0xa0, 0xcc, 0xf0, 0x02, 0x4a, 0x79, 0xc3, 0xde],
    [0xa3, 0xef, 0xea, 0x51, 0xe6, 0x6b, 0x18, 0xec, 0x1b, 0x2c, 0x80, 0xf7, 0x74, 0xe7, 0xff, 0x21],
    [0x5a, 0x6a, 0x54, 0x1e, 0x41, 0x31, 0x92, 0x35, 0xc4, 0x33, 0x07, 0x0a, 0xba, 0x7e, 0x0e, 0x34],
    [0x88, 0xb1, 0x98, 0x7c, 0xf3, 0x3d, 0x60, 0x6c, 0x7b, 0xca, 0xd3, 0x1f, 0x32, 0x65, 0x04, 0x28],
    [0x64, 0xbe, 0x85, 0x9b, 0x2f, 0x59, 0x8a, 0xd7, 0xb0, 0x25, 0xac, 0xaf, 0x12, 0x03, 0xe2, 0xf2]
]

# 常量 D，16 个 16 比特的常量（资料性附录中给出的 d0~d15）
D = [0x44d7, 0x26bc, 0x626b, 0x135e, 0x5789, 0x35e2, 0x7135, 0x09af,
     0x4d78, 0x2f13, 0x6bc4, 0x1af1, 0x5e26, 0x3c4d, 0x789a, 0x47ac]


class ZUC:
    """
    ZUC 序列密码算法类封装

    属性：
        KEY: 长度为 16 字节的密钥，列表中的每个元素为 8 位整数
        IV:  长度为 16 字节的初始向量
        S:   线性反馈移位寄存器（LFSR），包含 16 个 31 比特的数（整数）
        X:   比特重组输出的 4 个 32 比特字
        R1, R2: 非线性函数 F 的两个 32 比特记忆单元
        W:   非线性函数 F 的输出（32 比特字）
    """

    def __init__(self, key, iv):
        """
        初始化 ZUC 对象，设置密钥、初始向量，并构造初始的 LFSR 状态

        参数：
            key: 长度为 16 的列表，每个元素为 8 位整数
            iv:  长度为 16 的列表，每个元素为 8 位整数
        """
        # 存储密钥和初始向量
        self.KEY = key
        self.IV = iv

        # 初始化 LFSR 状态，S 为长度为 16 的列表
        # 每个 S[i] 由 KEY[i]、常量 D[i] 和 IV[i] 组合得到，
        # 具体为：S[i] = IV[i] | (D[i] << 8) | (KEY[i] << 23)
        self.S = [0] * 16

        # 比特重组输出的 4 个 32 位字，初始全为 0
        self.X = [0] * 4

        # 非线性函数 F 的中间变量
        self.R1 = 0
        self.R2 = 0
        self.W = 0

        # 初始化 LFSR 状态
        self._init_lfsr()

    @staticmethod
    def ROL(X, i):
        """
        在 32 位字中循环左移 i 位

        参数：
            X: 32 位整数
            i: 循环左移的位数
        返回：
            循环左移后的 32 位整数
        """
        return ((X << i) & 0xFFFFFFFF) | (X >> (32 - i))

    @staticmethod
    def L1(X):
        """
        32 位线性变换 L1

        定义：L1(X) = X ⊕ (X <<< 2) ⊕ (X <<< 10) ⊕ (X <<< 18) ⊕ (X <<< 24)

        参数：
            X: 32 位整数
        返回：
            经过 L1 线性变换后的 32 位整数
        """
        return (X ^ ZUC.ROL(X, 2) ^ ZUC.ROL(X, 10) ^ ZUC.ROL(X, 18) ^ ZUC.ROL(X, 24)) & 0xFFFFFFFF

    @staticmethod
    def L2(X):
        """
        32 位线性变换 L2

        定义：L2(X) = X ⊕ (X <<< 8) ⊕ (X <<< 14) ⊕ (X <<< 22) ⊕ (X <<< 30)

        参数：
            X: 32 位整数
        返回：
            经过 L2 线性变换后的 32 位整数
        """
        return (X ^ ZUC.ROL(X, 8) ^ ZUC.ROL(X, 14) ^ ZUC.ROL(X, 22) ^ ZUC.ROL(X, 30)) & 0xFFFFFFFF

    @staticmethod
    def S_box(X):
        """
        S盒变换函数

        将 32 位输入 X 拆分成 4 个 8 位字节，
        前 8 位分别由 S0 进行变换，后 8 位分别由 S1 进行变换
        最后将 4 个 8 位结果拼接成 32 位输出

        参数：
            X: 32 位整数
        返回：
            经过 S盒变换后的 32 位整数
        """
        # 将 X 拆分成 4 个字节
        bytes_in = [X >> 24, (X >> 16) & 0xFF, (X >> 8) & 0xFF, X & 0xFF]
        S_out = [0] * 4
        for i in range(4):
            # 根据索引决定使用 S0 或 S1
            m = bytes_in[i] >> 4  # 高 4 位
            n = bytes_in[i] & 0xF  # 低 4 位
            if i in [0, 2]:
                S_out[i] = S0[m][n]
            else:
                S_out[i] = S1[m][n]
        # 将4个8位结果拼接成32位整数
        return ((S_out[0] << 24) | (S_out[1] << 16) | (S_out[2] << 8) | S_out[3]) & 0xFFFFFFFF

    def _bit_reconstruction(self):
        """
        比特重组函数

        根据当前 LFSR 状态 S 计算 4 个 32 位字 X[0..3]：
            X[0] = (S[15] 高 16 位) ‖ (S[14] 低 16 位)
            X[1] = (S[11] 低 16 位) ‖ (S[9] 高 16 位)
            X[2] = (S[7] 低 16 位) ‖ (S[5] 高 16 位)
            X[3] = (S[2] 低 16 位) ‖ (S[0] 高 16 位)
        """
        # 右移15位得到高16位，直接取低16位则用 & 0xFFFF
        self.X[0] = (((self.S[15] >> 15) & 0xFFFF) << 16) | (self.S[14] & 0xFFFF)
        self.X[1] = ((self.S[11] & 0xFFFF) << 16) | ((self.S[9] >> 15) & 0xFFFF)
        self.X[2] = ((self.S[7] & 0xFFFF) << 16) | ((self.S[5] >> 15) & 0xFFFF)
        self.X[3] = ((self.S[2] & 0xFFFF) << 16) | ((self.S[0] >> 15) & 0xFFFF)

    def _F(self, X0, X1, X2):
        """
        非线性函数 F

        输入：3 个 32 位字 X0, X1, X2
        计算过程：
            W  = (X0 ⊕ R1) + R2    mod 2^32
            W1 = R1 + X1           mod 2^32
            W2 = R2 ⊕ X2
            R1 = S_box( L1( (W1 << 16) | (W2 >> 16) ) )
            R2 = S_box( L2( (W2 << 16) | (W1 >> 16) ) )
        同时更新全局变量 W, R1, R2
        """
        self.W = ((X0 ^ self.R1) + self.R2) % (2 ** 32)
        W1 = (self.R1 + X1) % (2 ** 32)
        W2 = self.R2 ^ X2
        # 拼接高低位后进行线性变换 L1 和 L2，再经过 S盒变换更新 R1, R2
        temp1 = ((W1 << 16) | (W2 >> 16)) & 0xFFFFFFFF
        self.R1 = self.S_box(self.L1(temp1))
        temp2 = ((W2 << 16) | (W1 >> 16)) & 0xFFFFFFFF
        self.R2 = self.S_box(self.L2(temp2))

    def _lfsr_with_initialisation_mode(self, u):
        """
        线性反馈移位寄存器（LFSR）的初始化模式更新

        计算公式：
            v = (2^15 * S[15] + 2^17 * S[13] + 2^21 * S[10] + 2^20 * S[4] + (1 + 2^8) * S[0]) mod (2^31-1)
            S_new = (v + u) mod (2^31-1)
            如果 S_new 为 0，则置为 (2^31-1)
            最后将 S 进行移位（丢弃最左边的元素，添加新的 S_new）

        参数：
            u: 来自 F 函数输出 W 的右移 1 位的值，即 W >> 1
        """
        # 根据公式计算中间变量 v
        v = ((2 ** 15) * self.S[15] + (2 ** 17) * self.S[13] +
             (2 ** 21) * self.S[10] + (2 ** 20) * self.S[4] +
             (1 + 2 ** 8) * self.S[0]) % (2 ** 31 - 1)
        # 计算新的寄存器值，注意加上 u 后再取模
        new_val = (v + u) % (2 ** 31 - 1)
        # 根据标准规定，当结果为 0 时应置为 (2^31-1)
        if new_val == 0:
            new_val = (2 ** 31 - 1)
        # 更新 LFSR：删除 S[0]，将新值添加到末尾
        self.S.append(new_val)
        del self.S[0]

    def _lfsr_with_work_mode(self):
        """
        线性反馈移位寄存器（LFSR）的工作模式更新

        工作模式与初始化模式类似，但没有外部输入 u。
        计算公式：
            S_new = (2^15 * S[15] + 2^17 * S[13] + 2^21 * S[10] + 2^20 * S[4] + (1 + 2^8) * S[0]) mod (2^31-1)
            如果 S_new 为 0，则置为 (2^31-1)
            更新 S 列表（左移）
        """
        new_val = ((2 ** 15) * self.S[15] + (2 ** 17) * self.S[13] +
                   (2 ** 21) * self.S[10] + (2 ** 20) * self.S[4] +
                   (1 + 2 ** 8) * self.S[0]) % (2 ** 31 - 1)
        if new_val == 0:
            new_val = (2 ** 31 - 1)
        self.S.append(new_val)
        del self.S[0]

    def _init_lfsr(self):
        """
        初始化 LFSR 的初始状态

        根据标准要求，利用密钥 KEY、初始向量 IV 和常量 D 构造初始状态 S[i]：
            S[i] = IV[i] | (D[i] << 8) | (KEY[i] << 23)
        """
        for i in range(16):
            self.S[i] = self.IV[i] | (D[i] << 8) | (self.KEY[i] << 23)

    def init_phase(self):
        """
        初始化阶段

        执行 32 次内部状态更新，过程如下：
            1. 执行比特重组，计算 X[0..3]
            2. 调用非线性函数 F，更新 R1, R2, W
            3. 调用 LFSR 的初始化模式更新，使用 (W >> 1) 作为输入
        同时打印中间状态信息（可根据需要移除打印代码）
        """
        self.print_LFSR("初始化阶段：线性反馈移位寄存器（LFSR）的初始状态：")

        print("开始 32 次初始化迭代：")
        for i in range(32):
            self._bit_reconstruction()
            self._F(self.X[0], self.X[1], self.X[2])
            # LFSR 初始化模式更新，输入为 W >> 1
            self._lfsr_with_initialisation_mode(self.W >> 1)
            # 输出中间状态信息
            print(f"第 {i + 1:2d} 轮: ", end='')
            self.print_register_status()
        self.print_LFSR("初始化结束，当前 LFSR 状态：")

    def first_work_phase(self):
        """
        工作阶段单步更新

        执行一次比特重组、非线性函数 F 计算，并调用 LFSR 工作模式更新
        """
        self._bit_reconstruction()
        self._F(self.X[0], self.X[1], self.X[2])
        self._lfsr_with_work_mode()

    def generate_keystream(self, n):
        """
        产生密钥流

        参数：
            n: 需要产生的密钥字（32 位整数）的个数
        返回：
            一个列表，每个元素为一个 32 位的密钥字
        """
        keystream = []
        for i in range(n):
            # 1. 比特重组
            self._bit_reconstruction()
            # 2. 非线性函数 F 计算，输出 W 与 X[3] 异或，即输出单个密钥字
            self._F(self.X[0], self.X[1], self.X[2])
            # 每次密钥字为 F 输出 W 与 X[3] 异或
            z = self.W ^ self.X[3]
            keystream.append(z)
            # 3. LFSR 工作模式更新
            self._lfsr_with_work_mode()
            # 输出调试信息（可根据需要注释掉）
            print(f"密钥字 {i}: ", end='')
            self.print_register_status()
        return keystream

    def print_LFSR(self, msg="当前 LFSR 状态："):
        print(msg)
        for s in range(16):
            print(f"S[{s}] = {hex(self.S[s])}", end=' ')
            # 每 8 个一行
            if (s + 1) % 8 == 0:
                print()

    def print_register_status(self):
        for j in range(4):
            print('X' + str(j) + ':\033[1;31m' + hex(self.X[j]).replace('0x', '') + '\033[0m', end=' ')
        print('R1' + ':\033[1;34m' + hex(self.R1).replace('0x', '') + '\033[0m', end=' ')
        print('R2' + ':\033[1;34m' + hex(self.R2).replace('0x', '') + '\033[0m', end=' ')
        print('W' + ':\033[1;35m' + hex(self.W).replace('0x', '') + '\033[0m', end=' ')
        print('S15' + ':\033[1;36m' + hex(self.S[15]).replace('0x', '') + '\033[0m', end=' ')
        print()


if __name__ == '__main__':
    # 简单测试向量：使用全 0 的 128 比特密钥和初始向量
    # key = [0x00] * 16
    # iv = [0x00] * 16
    # key = [0xff] * 16
    # iv = [0xff] * 16
    # 随机测试向量：使用随机生成的 128 比特密钥和初始向量
    key = [0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae, 0xb5, 0x8f, 0x64, 0x1d, 0xb1, 0x7b, 0x45, 0x5b]
    iv = [0x84, 0x31, 0x9a, 0xa8, 0xde, 0x69, 0x15, 0xca, 0x1f, 0x6b, 0xda, 0x6b, 0xfb, 0xd8, 0xc7, 0x66]

    # 创建 ZUC 对象
    zuc_cipher = ZUC(key, iv)
    # 执行初始化阶段
    zuc_cipher.init_phase()
    # 执行工作步骤的第一步部分
    zuc_cipher.first_work_phase()
    # 生成若干个密钥字
    keywords = zuc_cipher.generate_keystream(2)
    print("产生的密钥流：")
    for i, z in enumerate(keywords):
        print(f"Z{i} = {hex(z)}")
