# AOS 需求文档 · 版本 B：从零编写的 Rust 能力式微内核

> 前置阅读：`00-core-spec.md`。本文件只规定平台相关部分，所有语义以核心规格为准。
>
> 建议先完成版本 A 的核心库里程碑（核心 M0–M3）。版本 B 直接复用 `no_std` 核心 crate，并且必须通过同一套一致性测试。

---

## B1. 定位

版本 B 存在的理由只有一个：把核心原则 **P3（不可逆只发生在出口）** 和 **P6（能力而非身份）** 从"靠配置保证"变成"靠结构保证"。

- 在版本 A 里，出口强制依赖 nftables 规则配置正确。
- 在版本 B 里，**网卡的能力在整个系统里只存在于一个进程中**。其他进程从结构上就没有对外通信的手段，不存在"配错规则"这种失败方式。

规模粗估为版本 A 的 3–10 倍。主要成本来自驱动、调试和 TLS（猜测，依据是同类教学/研究型微内核的经验）。

---

## B2. 目标平台

- 只支持 QEMU，不支持任何实体硬件。
- 主目标：`qemu-system-aarch64 -machine virt`（在 Apple Silicon 宿主上可用 `-accel hvf`）。
- 次目标：`qemu-system-x86_64 -machine q35`。B-6 之前 MAY 不支持。
- 设备只支持 virtio-mmio（aarch64）或 virtio-pci（x86_64）：virtio-blk、virtio-net、virtio-rng、virtio-console。v1 不需要 virtio-gpu，见 §B9。
- 启动：aarch64 用 QEMU `-kernel` 直接加载 ELF，读取 DTB；x86_64 用 Limine 引导协议。

---

## B3. 内核需求

### B3.1 必须提供

| 能力 | 要求 |
|---|---|
| 内存管理 | 物理页分配；页表管理（aarch64 4 KiB 页，48 位地址空间） |
| 地址空间 | 每个进程独立地址空间；内核与用户隔离 |
| 线程与调度 | 抢占式，固定优先级 + 同优先级轮转；v1 单核，SMP 在 B-7 之后 |
| IPC | 同步端点（call/reply，可携带能力传递）；异步通知（位图信号） |
| 能力系统 | 类型化能力：Untyped、Frame、PageTable、AddressSpace、Thread、Endpoint、Notification、IRQ、DeviceMMIO；支持派生（含权限衰减）、复制、撤销（级联） |
| 中断 | 以通知的形式投递给用户态驱动 |
| 定时器 | 单调时钟；超时 IPC |
| 调试 | 串口日志；QEMU GDB stub 可用；内核 panic 时打印能力表摘要 |

### B3.2 明确不做

POSIX、fork/exec、内核内文件系统、内核内网络栈、内核内驱动（只保留中断控制器和定时器）、形式化验证。

### B3.3 规模约束

内核 SHOULD 少于 15k 行 Rust。超过时，必须在 `DECISIONS.md` 里写明原因。

### B3.4 设计参考

能力模型参考 seL4 的思路（Untyped 内存派生、CNode 能力空间），但**不要求**兼容 seL4 的 API。

---

## B4. 用户态服务与能力分配

这一节是版本 B 的核心。下表规定了**谁持有什么能力**。能力分配表本身就是安全规格，任何偏离都 MUST 记入 `DECISIONS.md`。

| 进程 | 持有的关键能力 | 不持有 |
|---|---|---|
| root task | 启动时的全部 Untyped；负责按本表分发能力，之后**退出** | — |
| memory server | Untyped 的子集；为其他进程分配内存 | 设备、网络 |
| virtio-blk driver | blk 设备的 MMIO + IRQ | 网络 |
| virtio-net driver | net 设备的 MMIO + IRQ；**只与 netstack 之间**有端点 | 其他任何端点 |
| netstack（smoltcp） | 与 net driver 的端点；对外提供两类端点：**出站端点**和**入站监听端点** | 存储 |
| **egress gateway** | netstack 的**出站端点**（全系统唯一）；密钥区存储端点 | 对象存储的写端点（结果经 ingress 写回） |
| confirm service | netstack 的入站监听端点（只限配对端口）；egress gateway 的放行端点 | 出站端点 |
| storage server | blk driver 端点；实现日志段与 CAS | 网络 |
| core server（aos-core） | storage 端点；对其他服务提供对象、分支、能力、策略端点 | 网络、设备 |
| action runtime（wasmi） | core server 的受限端点（按调用注入） | 网络、存储直连 |
| agent host | core server 的 agent 端点；egress gateway 的意图提交端点（只能提交，不能放行） | 网络 |
| view server | netstack 的入站监听端点（只限界面端口）；core server 的 human 端点 | 出站端点 |
| ingress gateway | core server 的入口写端点；egress gateway 的取数回调 | 出站端点 |

不变量（MUST，由测试验证）：

1. 出站端点的能力在任意时刻只存在于 egress gateway 的能力空间里。
2. root task 完成分发后退出，系统里不再存在持有全部 Untyped 的进程。
3. agent host 和 action runtime 的能力空间里，没有任何设备能力或 netstack 能力。

---

## B5. 网络能力拆分

- netstack 对外提供两类能力：
  - **出站连接能力**：可以发起 TCP 连接、发送 UDP。只交给 egress gateway。
  - **入站监听能力**：绑定在某个端口上，只能 accept 进入的连接，不能主动发起连接。交给 view server 和 confirm service，各自只能监听自己的端口。
- DNS 解析只在 egress gateway 内部完成。
- 取外部数据（入口）与核心规格一致：由 egress gateway 代取，取回的字节交给 ingress gateway 打标签。

---

## B6. 存储

- 不实现通用文件系统。storage server 直接在 virtio-blk 上管理三个区域：
  - **超级块**：双副本，带 CRC 和代数号；
  - **日志区**：只追加的段，带 CRC；
  - **CAS 区**：简单的 extent 分配器，加一张哈希 → extent 的索引（索引本身也写入日志，可重建）。
- 崩溃一致性：先写日志段并 flush，再更新超级块。启动时从最后一个有效的超级块恢复，回放日志，并校验哈希链。
- 实现核心库中的存储 trait，使核心一致性套件能在版本 B 的存储后端上运行（经 §B10 的 IPC 适配层）。

---

## B7. 密码学与 TLS

- 哈希与签名使用 RustCrypto 的 `sha2`、`p256`（`no_std`）。
- 随机数来自 virtio-rng，混入内核熵池后通过能力提供给需要的进程。
- **TLS 是主要风险点**：
  - 首选 rustls 的 `no_std + alloc` 模式，配合一个基于 RustCrypto 的 crypto provider；
  - 备选 `embedded-tls`（只支持 TLS 1.3 客户端）；
  - 不允许把 TLS 终止在宿主机侧的代理上，因为那样相当于把出口挪出了 AOS 的边界。
  - 在 B-4 开始前，必须先完成一个技术验证：在 QEMU 中从 egress gateway 成功与一个公网 HTTPS 服务完成握手。

---

## B8. 动作、作业与 agent

- **动作**：在 wasmi（`no_std` WASM 解释器）中执行，使用与版本 A 完全相同的 WASM 二进制和宿主 ABI（核心 §8.4）。性能低于 wasmtime，v1 可以接受。
- **作业**：版本 B 内部没有 Python。所有重计算都是**远程作业**（核心 §8.5），经 egress gateway 发往外部计算资源。
  - v1 的外部计算资源可以是宿主机上运行的一个"计算 worker"进程（通过 QEMU 端口转发连接）。它在 AOS 的边界之外，按外部世界对待。
  - 因此在版本 B 中，`ml.run.launch_local` 和 `ml.model.quantize` 映射为远程作业，可逆性为 `compensate`。这个差异 MUST 体现在动作目录的版本 B 实现中，并在 `DECISIONS.md` 里记录。
- **agent host**：需要 HTTP/JSON 客户端（`no_std + alloc`）。模型调用作为出口意图提交给 egress gateway，由常设规则放行（核心 §11.5）。MCP 接口通过 view server 的入站端口对外提供，以便宿主机上的开发工具连接；但真正驱动任务的 agent 运行在 AOS 内部。

---

## B9. 人的界面

- 版本 B 的 v1 **无头运行**：view server 通过入站监听端口提供 Web 界面，用户在宿主机浏览器里经 QEMU 端口转发访问。
- 这不削弱安全性：核心规格本来就把屏幕视为不可信，所有需要信任的信息都显示在 iPhone 上。
- virtio-gpu 本地显示属于 v2，届时可以先做一个只显示状态和配对二维码的帧缓冲界面。

---

## B10. 测试基础设施

- **内核单元测试**：在 QEMU 中运行，通过串口输出结果，由宿主机脚本判定通过或失败。
- **一致性套件**：在宿主机上运行 `aos-conformance`，通过一个"IPC 适配层"（经 virtio-console 或端口转发）调用 AOS 内的 core server。
- **能力分配审计**：提供一个 debug 能力，可以导出每个进程的能力空间摘要；测试据此验证 §B4 的三条不变量。
- **模糊测试**：IPC 消息解析、CBOR 解码、日志恢复，三项都要模糊测试，在宿主机上用 `cargo fuzz` 跑 `no_std` crate。

---

## B11. 平台安全测试

| 编号 | 测试 | 期望结果 |
|---|---|---|
| BS1 | 能力审计：出站端点只出现在 egress gateway 中 | 通过 |
| BS2 | root task 分发完成后，系统中不存在持有全部 Untyped 的进程 | 通过 |
| BS3 | 构造一个恶意的 WASM 动作，尝试越权调用宿主 ABI | 事务中止，并写入 ActionViolation |
| BS4 | 篡改磁盘上日志区的任意字节后重启 | 检测到哈希链断裂，进入只读安全模式 |
| BS5 | 任务执行中强制关闭虚拟机后重启 | 日志一致，未完成的事务不生效 |
| BS6 | view server 尝试使用入站能力主动发起连接 | 内核或 netstack 拒绝 |
| BS7 | 撤销 agent host 的能力后，它的后续调用 | 全部失败 |
| BS8 | 审批通过后替换出口载荷 | egress gateway 拒绝执行 |

---

## B12. 里程碑

| 里程碑 | 内容 | 验收 |
|---|---|---|
| B-0 | 在 aarch64 virt 上启动，串口打印，异常向量，页表 | 串口输出 + 内核单元测试 |
| B-1 | 线程、调度、地址空间、同步 IPC | IPC ping-pong 测试；上下文切换测试 |
| B-2 | 能力系统（派生、撤销）、root task 分发、memory server | 能力单元测试；BS2 |
| B-3 | virtio-blk 驱动 + storage server + 核心 crate 移植 | 一致性套件中日志、事务、分支、撤销部分；BS4、BS5 |
| B-4 | TLS 技术验证（见 §B7）→ virtio-net + netstack + egress gateway | 与公网 HTTPS 服务握手；BS1、BS6、BS8 |
| B-5 | wasmi 动作运行时、能力令牌、策略、开发确认器 | 一致性套件全部；BS3、BS7 |
| B-6 | agent host、view server（无头）、ML 提供方（远程作业版） | E2E-ML（开发确认器，计算 worker 在宿主机上） |
| B-7 | iPhone 配对与审批 | 真机完成 E2E-ML 的确认步骤 |
| B-8 | x86_64 q35 移植；SMP（可选） | B-0 至 B-7 的测试在 x86_64 上通过 |

---

## B13. 风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| TLS 在 `no_std` 下不成熟 | B-4 卡住，出口无法连接外部 | B-4 之前先做技术验证；准备 `embedded-tls` 备选 |
| 内核并发 bug 难以调试 | 进度失控 | v1 只做单核；QEMU GDB stub + 确定性回放（`-icount`）；每条 IPC 路径都写测试 |
| virtio 驱动的边角行为 | 数据损坏 | 只支持 QEMU 的 virtio 实现；写入后回读校验 |
| wasmi 性能 | 大批量数据动作变慢 | 重计算一律走作业；动作只做元数据级操作 |
| 能力分配被临时"打洞"以赶进度 | 结构性保证失效 | §B4 表格的任何偏离都必须记录在 `DECISIONS.md`，BS1 和 BS2 测试不得跳过 |
