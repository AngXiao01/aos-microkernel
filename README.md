# aos-microkernel

AOS（agent-native OS）的微内核版：从零编写的 Rust 能力式微内核，跑在 QEMU 的 aarch64 `virt` 机器上。

操作系统掌管对象图（真实状态）和动作目录（每个可执行动作的说明书）。人看渲染出来的界面，agent 看结构化的查询结果，两边改的是同一份数据。内部的修改都可以撤销；不可逆的操作只发生在出口，出口要由人放行。

本仓库自成一体。唯一的规格是 [`SPEC.md`](SPEC.md)：第一部分是系统语义，第二部分是平台实现。规格没有写明的实现选择记在 [`DECISIONS.md`](DECISIONS.md)。规格内部的矛盾与缺口记在 [`QUESTIONS.md`](QUESTIONS.md)。§B4 的能力分配表就是安全规格，任何偏离都必须写进 `DECISIONS.md`。

许可证是 [MIT](LICENSE)。

## 当前进度

下面只写 `main` 上已经合入的范围。核心里程碑见 SPEC §17，平台里程碑见 SPEC §B12，两套交错推进。没进 `main` 的工作不记成已发布。

### §17 核心里程碑

这些是宿主机上的核心库。动作运行时、能力令牌、策略和开发确认器在这里有测试，还不等于平台里程碑 B-5。

| 里程碑 | 状态 | 验收 |
|---|---|---|
| M0 核心库骨架：类型、对象、CBOR、哈希 | 完成 | `make test-core`：单元测试，以及每项 10⁴ 例的 CBOR 属性测试 |
| M1 日志、事务、分支、变更单、撤销 | 完成 | `make test-core`：§16.1 的日志、事务、分支、撤销（含两个 10⁴ 例的属性测试）；`cargo run --release -p aos-conformance --example perf` 测 §7.8 |
| M2 动作声明、WASM 运行时、宿主 ABI、能力令牌 | 完成 | `make test-core`：§16.1 的能力（衰减不变量、越权拒绝、额度扣减，含属性测试）和动作沙箱（未声明读写、直接 I/O、出口、燃料、前置条件、污点） |
| M3 出口意图、策略引擎、出口闸门、开发确认器 | 完成 | `make test-core`：§16.1 的出口（无放行不执行、载荷篡改、签名重放、过期签名）、策略（优先级与默认 confirm，含 10⁴ 例属性测试）、污点（收件方带污点必须确认），以及一条端到端流程 |

M4 至 M8 尚未开始。

### §B12 平台里程碑

| 里程碑 | 状态 | 验收 |
|---|---|---|
| B-0 aarch64 virt 启动、串口、异常向量、页表 | 完成 | `make test-kernel`：EL1 进入（512 MiB）与 EL2 进入（4 GiB） |
| B-1 线程、调度、地址空间、同步 IPC | 完成 | `make test-kernel`：IPC ping-pong（2000 次往返，16 字消息）、三线程抢占下的全寄存器（含 FP/SIMD、FPCR）完整性、超时、故障隔离、通知、FIFO、权限 |
| B-2 能力系统（派生、撤销）、root task 分发、memory server | 完成 | `make test-kernel`：能力单元测试（retype、衰减、派生树、对象销毁、撤销 Untyped、帧映射）与 BS2（root 分发后退出，memory server 发放帧，无进程持有全部 Untyped） |
| B-3 virtio-blk 驱动、storage server、核心 crate 接到磁盘上 | 完成 | `make test-b3`：一致性套件里的日志、事务、分支、撤销，经 virtio-blk 上的存储服务跑通；BS4（篡改日志后进入只读安全模式）、BS5（断电后未完成的写入不生效） |

B-4 及之后尚未进入 `main`。

## 下一步

下一档是 **B-4**（SPEC §B12；还没有合入 `main`）。先做 TLS 技术验证（§B7），再做 virtio-net、netstack 和 egress gateway。验收：与一个公网 HTTPS 服务完成握手；BS1、BS6、BS8。

B-4 之后是 **B-5**：wasmi 动作运行时、能力令牌、策略、开发确认器。验收：一致性套件全部；BS3、BS7。宿主机上的 M2、M3 已经覆盖这些库的核心测试；B-5 要求的是它们在客户机里跑通，并且一致性套件全部加上 BS3、BS7。

再往后的 M4–M8 和 B-6–B-8 以 SPEC §17、§B12 为准。本仓库没有另一份路线图。

## 构建，以及在 QEMU 里跑

依赖：Rust（版本与 `aarch64-unknown-none`、`aarch64-unknown-none-softfloat`、`wasm32-unknown-unknown` 由 `rust-toolchain.toml` 固定为 1.97.0，rustup 会安装）、QEMU ≥ 8（`qemu-system-aarch64`）。调试另需 `gdb-multiarch`。Ubuntu 上：

```bash
apt-get install -y qemu-system-arm gdb-multiarch
```

| 命令 | 作用 |
|---|---|
| `make test` | 核心库测试、`no_std` 构建检查、QEMU 内核单测。不含下面的 B-3 磁盘验收 |
| `make test-core` | 核心库在宿主机上的单元测试与属性测试 |
| `make check-nostd` | 核心库为 `aarch64-unknown-none` 构建 |
| `make test-kernel` | `kernel/scripts/ktest.sh`：构建带测试的内核并在 QEMU 中运行。日志在 `kernel/target/ktest/` |
| `make test-b3` | B-3 验收。先构建带 `debug-syscalls` 的内核，再由 `tests/platform` 挂上 virtio-blk 磁盘和 virtio-console，跑日志/事务/分支/撤销以及 BS4、BS5 |
| `make lint` | rustfmt 与 clippy（警告视为错误） |
| `make run` | 在 QEMU 中启动内核，串口接在终端上。`Ctrl-A X` 退出。这条命令不挂磁盘，存储服务不会起来 |
| `make gdb` | 同 `make run`，但在 `:1234` 等待调试器 |

调试：

```bash
gdb-multiarch kernel/target/aarch64-unknown-none-softfloat/release/aos-kernel -ex 'target remote :1234' -ex 'break kernel_main' -ex continue
```

`make run` 看到的是内核启动横幅、内存与中断初始化，以及 root task 的分发结果。要看磁盘上的日志、事务和 BS4/BS5，用 `make test-b3`。

## 布局

```
core/aos-types/    对象、类型、确定性 CBOR、SHA-256、ULID（no_std + alloc）
core/aos-log/      只追加、哈希链接的日志，存储后端经 LogStorage trait（no_std）
core/aos-branch/   事务、分支、提交、撤销、变更单（no_std）
core/aos-cap/      能力令牌：签发、衰减、校验、额度、撤销（no_std）
core/aos-action/   动作声明、输入绑定、前置条件与代价表达式、宿主 ABI 定义（no_std）
core/aos-runtime/  WASM 动作运行时（wasmi），强制执行声明与能力（no_std）
core/aos-policy/   常设规则与求值（no_std）
core/aos-confirm/  审批请求、确认器签名与一次性校验、开发确认器（no_std）
core/aos-egress/   出口闸门：载荷重算、审批匹配、只执行一次（no_std）
core/aos-storage/  存储服务用的磁盘卷：超级块、只追加日志、内容寻址区（no_std）
tests/conformance/ 核心一致性套件（§16.1），与存储后端无关
tests/platform/    B-3 的宿主机验收：virtio-blk 上的一致性子集，以及 BS4、BS5
actions/           WASM 动作：sdk（guest 侧库）、test-script（运行时测试用的脚本动作）
kernel/            微内核：启动、异常、页表、FDT、GIC、定时器、线程、调度、IPC、virtio 设备发现
kernel/abi/        内核与用户态共用的 ABI（系统调用号、消息布局、用户地址布局）
kernel/scripts/    QEMU 启动（qemu.sh）与内核测试（ktest.sh）
services/          用户态：rt、root、memory、blk、hostlink、storage、virtio，以及内核测试用的 ktest-user
```

根目录和 `kernel/`、`services/`、`actions/` 是分开的 Cargo workspace。§18 里的 `compute-worker/`、`view/`、`confirmer-ios/` 留到对应里程碑再加。
