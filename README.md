# GMalg

国密算法的Python实现

本项目使用python实现国密算法，包含SM2、SM3、SM4、SM9、ZUC，支持国密算法的加解密、签名验签等功能。

其中SM2、SM3、SM4、ZUC从零实现，SM9使用了[gongxian-ding/gmssl-python](https://github.com/gongxian-ding/gmssl-python.git)
（见`gmssl/`）
的SM9相关实现。

`doc/`目录下存放了国密算法的相关文档，包括算法原理、实现细节等。文档均下载于
[国家标准全文公开系统](https://openstd.samr.gov.cn/bzgk/gb/index)。

# Usage

克隆本项目代码：

```bash
git clone https://github.com/bubumua/GMalg.git
```

# 参考与引用

- 见doc目录下文件
- https://github.com/gongxian-ding/gmssl-python.git
