# aos-microkernel

AOS（agent-native OS）的微内核版：从零编写的 Rust 能力式微内核，运行在 QEMU 中。

本仓库自成一体，不依赖任何其他仓库。唯一的规格文件是 [`SPEC.md`](SPEC.md)，第一部分规定系统语义，第二部分规定平台实现。

## 给实现 agent

1. 先读 `SPEC.md` 的 §0，再通读全文。
2. 按 §18 的仓库布局组织代码。核心库、人的界面、iPhone 确认器、宿主机上的计算 worker 都在本仓库内实现。
3. §B4 的能力分配表就是安全规格，任何偏离都必须写进 `DECISIONS.md`。
4. B-4 之前先完成 TLS 技术验证（§B7）。

规格没有规定的细节记在 [`DECISIONS.md`](DECISIONS.md)，规格内部的矛盾与缺口记在 [`QUESTIONS.md`](QUESTIONS.md)。

## 进度

| 里程碑 | 状态 | 验收 |
|---|---|---|
| M0 核心库骨架：类型、对象、CBOR、哈希 | 完成 | `make test-core`：单元测试 + 每项 10⁴ 例的 CBOR 属性测试 |
| M1 日志、事务、分支、变更单、撤销 | 完成 | `make test-core`：§16.1 日志、事务、分支、撤销部分（含两个 10⁴ 例的属性测试）；`cargo run --release -p aos-conformance --example perf` 测 §7.8 |
| M2 动作声明、WASM 运行时、宿主 ABI、能力令牌 | 完成 | `make test-core`：§16.1 能力（衰减不变量、越权拒绝、额度扣减，含属性测试）与动作沙箱（未声明读写、直接 I/O、出口、燃料、前置条件、污点） |
| B-0 aarch64 virt 启动、串口、异常向量、页表 | 完成 | `make test-kernel`：EL1 进入（512 MiB）与 EL2 进入（4 GiB）两种配置下的内核单元测试 |
| B-2 能力系统（派生、撤销）、root task 分发、memory server | 完成 | `make test-kernel`：能力单元测试（retype、衰减、派生树、对象销毁、撤销 Untyped、帧映射）与 BS2（root 分发后退出，memory server 发放帧，无进程持有全部 Untyped） |
| B-1 线程、调度、地址空间、同步 IPC | 完成 | `make test-kernel`：IPC ping-pong（2000 次往返，16 字消息）、三线程抢占下的全寄存器（含 FP/SIMD、FPCR）完整性、超时、故障隔离、通知、FIFO、权限 |

## 开发

依赖：Rust（版本与 aarch64、wasm32 目标由 `rust-toolchain.toml` 固定，rustup 会自动安装）、QEMU ≥ 8（`qemu-system-aarch64`），调试另需 `gdb-multiarch`。Ubuntu 上：

```bash
apt-get install -y qemu-system-arm gdb-multiarch
```

| 命令 | 作用 |
|---|---|
| `make test` | 全部测试：核心库、`no_std` 构建检查、QEMU 内核单测 |
| `make test-core` | 核心库在宿主机上的单元测试与属性测试 |
| `make check-nostd` | 核心库为 `aarch64-unknown-none` 构建 |
| `make test-kernel` | `kernel/scripts/ktest.sh`：构建带测试的内核并在 QEMU 中运行，日志在 `kernel/target/ktest/` |
| `make lint` | rustfmt 与 clippy（警告视为错误） |
| `make run` | 在 QEMU 中启动内核，`Ctrl-A X` 退出 |
| `make gdb` | 同上，但等待调试器连接 `:1234` |

调试：

```bash
gdb-multiarch kernel/target/aarch64-unknown-none-softfloat/release/aos-kernel -ex 'target remote :1234' -ex 'break kernel_main' -ex continue
```

## 布局

```
core/aos-types/   对象、类型、确定性 CBOR、SHA-256、ULID（no_std + alloc）
core/aos-log/     只追加、哈希链接的日志，存储后端经 LogStorage trait（no_std）
core/aos-branch/  事务、分支、提交、撤销、变更单（no_std）
core/aos-cap/     能力令牌：签发、衰减、校验、额度、撤销（no_std）
core/aos-action/  动作声明、输入绑定、前置条件与代价表达式、宿主 ABI 定义（no_std）
core/aos-runtime/ WASM 动作运行时（wasmi），强制执行声明与能力（no_std）
tests/conformance/ 核心一致性套件（§16.1），与存储后端无关
actions/          WASM 动作：sdk（guest 侧库）、test-script（运行时测试用的脚本动作）
kernel/           微内核：启动、异常、页表、FDT、GIC、定时器、线程、调度、IPC；scripts/ 下是 QEMU 启动与测试脚本
kernel/abi/       内核与用户态共用的 ABI（系统调用号、消息布局、用户地址布局）
services/         用户态程序：rt（运行时）、root（root task）、memory（memory server）、ktest-user（内核测试驱动的用户程序）
```

§18 规定的其余目录（`compute-worker/`、`view/`、`confirmer-ios/`）在对应里程碑创建。
