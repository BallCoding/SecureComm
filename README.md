# SecureComm

SecureComm 是一个面向课程项目/实验场景的高安全通信工具，支持文本与任意文件（图片、文档、压缩包等二进制数据）的加密传输与完整性校验。

项目核心目标：
- 提供可运行、可复用的加密通信代码；
- 采用现代密码学算法组合，避免“简单加密”；
- 支持命令行与交互式两种使用方式；
- 具备较完整的工程结构、测试与文档。

---

## 1. 项目功能总览

本项目已实现以下独立功能模块：

1. 用户密钥管理
- 生成用户加密密钥与签名密钥；
- 导出/导入公钥，便于双方交换身份材料。

2. 文本加密通信
- 发送方对文本进行端到端加密并附带签名；
- 接收方验证签名后解密，确保机密性与来源可信。

3. 文件加密通信（图片/文档/任意二进制）
- 对文件进行分块加密；
- 支持解密后完整性校验（SHA-256）。

4. 文件签名与验签
- 支持对文件生成独立签名文件；
- 验签可检测文件是否被篡改。

5. 口令保险箱（Vault）
- 使用口令对本地敏感文本加密保存；
- 支持口令轮换。

6. 审计日志
- 记录关键操作行为（如加解密、签名、验签等），便于追踪。

---

## 2. 密码学方案说明

项目主要采用如下算法组合：

1. 混合加密方案
- `X25519`：密钥协商（ECDH）
- `HKDF-SHA256`：会话密钥派生
- `AES-256-GCM`：对称加密（带认证）

2. 数字签名
- `Ed25519`：消息与文件签名/验签

3. 口令派生
- 默认：`Argon2id`
- 兼容：`PBKDF2`

说明：以上属于当前工程中较强且常用的现代密码学组合，适合课程项目中“安全性较高”的实现要求。

---

## 3. 项目目录结构

```text
SecureComm/
├─ src/securecomm/
│  ├─ crypto/              # 密码学核心模块
│  ├─ services/            # 业务服务层
│  ├─ cli/                 # 命令行与交互入口
│  ├─ constants.py
│  ├─ errors.py
│  └─ main.py
├─ tests/                  # 集成测试
├─ docs/                   # 说明文档
├─ main.py                 # 本地启动入口
├─ requirements.txt
├─ pyproject.toml
├─ LICENSE
├─ THIRD_PARTY_NOTICES.md
└─ README.md
```

---

## 4. 环境要求

1. Python 版本
- 推荐 `Python 3.11+`（当前项目已在 3.13 环境测试）

2. 依赖安装

```bash
python -m pip install -r requirements.txt
```

如果你的环境无法直接联网安装，也可以使用项目内本地依赖目录（如 `vendor/`）方案，但默认推荐正常安装依赖。

---

## 5. 快速开始（最小可用流程）

### 第一步：生成双方密钥

```bash
python main.py keygen --user alice
python main.py keygen --user bob
```

### 第二步：文本加密与解密

```bash
python main.py encrypt-text --sender alice --recipient bob --text "hello bob" --output output/msg.smsg
python main.py decrypt-text --recipient bob --sender alice --input output/msg.smsg
```

### 第三步：文件加密与解密（图片/文档同理）

```bash
python main.py encrypt-file --sender alice --recipient bob --input sample.png --output output/sample.sfile
python main.py decrypt-file --recipient bob --sender alice --input output/sample.sfile --output output/sample.dec.png
```

### 第四步：签名与验签

```bash
python main.py sign-file --signer alice --input report.pdf --output output/report.ssig
python main.py verify-file --signer alice --input report.pdf --signature output/report.ssig
```

### 第五步：保险箱加密与解密

```bash
python main.py vault-encrypt --text "local secret" --password "YourStrongPwd2026" --output output/local.svault
python main.py vault-decrypt --password "YourStrongPwd2026" --input output/local.svault
```

---

## 6. 交互式模式

不带参数启动即可进入菜单：

```bash
python main.py
```

可按数字选择操作（生成密钥、文本/文件加解密、签名验签、保险箱等）。

---

## 7. 主要命令参考

1. 密钥管理
- `keygen --user <id> [--overwrite]`
- `users [--json]`
- `export-public --user <id> [--output <file>]`
- `import-public --input <file>`

2. 文本通信
- `encrypt-text --sender <id> --recipient <id> --text <msg> [--aad <aad>] [--output <file>]`
- `decrypt-text --recipient <id> --sender <id> --input <file>`

3. 文件通信
- `encrypt-file --sender <id> --recipient <id> --input <file> [--output <file>] [--chunk-size <bytes>]`
- `decrypt-file --recipient <id> --sender <id> --input <file> --output <file>`

4. 签名验签
- `sign-file --signer <id> --input <file> [--output <file>]`
- `verify-file --signer <id> --input <file> --signature <file>`

5. 保险箱
- `vault-encrypt --text <text> --password <pwd> [--output <file>] [--pbkdf2]`
- `vault-decrypt --password <pwd> --input <file>`
- `vault-rotate --old-password <pwd> --new-password <pwd> --input <file> --output <file> [--pbkdf2]`

6. 审计
- `audit --summary`
- `audit --limit <n> [--json]`

---

## 8. 第三方程序调用（作为库使用）

你可以直接在 Python 中调用服务层 API：

```python
from pathlib import Path
from securecomm.services.key_service import KeyService
from securecomm.services.message_service import MessageService

keys = KeyService()
msg = MessageService()

keys.create_user("alice")
keys.create_user("bob")

enc = msg.encrypt_text(
    sender_id="alice",
    recipient_id="bob",
    text="hello from api",
    output_path=Path("output/api_msg.smsg")
)

dec = msg.decrypt_from_file(
    recipient_id="bob",
    sender_id="alice",
    input_path=Path("output/api_msg.smsg")
)
print(dec["text"])
```

---

## 9. 测试

运行测试：

```bash
python -m unittest discover -s tests -v
```

---

## 10. 安全使用建议（务必阅读）

1. 不要提交私钥或密文产物到代码仓库
- `keys/`、`output/`、`*.pem` 等应始终忽略。

2. 不要在共享终端中明文输入敏感口令
- 推荐在受控环境运行，必要时改成隐藏输入方式。

3. 公钥导入前建议做人为核验
- 核对对方公钥指纹，防止中间人替换。

4. 本项目更适合课程设计、原型与实验
- 若用于生产环境，需继续加强：密钥托管、访问控制、日志脱敏、密钥轮换策略等。

---

## 11. 许可证与第三方说明

- 本项目许可证：见 `LICENSE`
- 第三方依赖许可证说明：见 `THIRD_PARTY_NOTICES.md`

---

## 12. 常见问题（FAQ）

1. 为什么解密失败？
- 常见原因：发送方/接收方 ID 对不上、导入了错误公钥、密文文件被修改。

2. 为什么验签失败？
- 常见原因：签名文件与原文件不匹配，或使用了错误签名者公钥。

3. 可以加密多大文件？
- 取决于机器内存与参数设置；当前是分块处理，但仍建议在可控范围内使用并逐步优化流式处理。

---
