# aos-microkernel

AOS 版本 B：从零编写的 Rust 能力式微内核，运行在 QEMU 中。

- 平台规格：[`02-version-B-microkernel.md`](02-version-B-microkernel.md)
- 核心规格与核心库：[AngXiao01/aos-core](https://github.com/AngXiao01/aos-core)（必读，语义以它为准）
- 另一个版本：[AngXiao01/aos-linux](https://github.com/AngXiao01/aos-linux)

## 给实现 agent

1. 把 `aos-core` 克隆到本仓库同级目录（`../aos-core`），先读 `../aos-core/00-core-spec.md`，再读本仓库的平台规格。
2. 本仓库直接复用 `aos-core` 中的 `no_std` crate，只实现内核、驱动、用户态服务和能力分配。
3. 平台规格 §B4 的能力分配表就是安全规格，任何偏离都必须写进 `DECISIONS.md`。
4. B-4 之前先完成 TLS 技术验证（§B7）。
