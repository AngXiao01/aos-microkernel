# aos-microkernel

AOS（agent-native OS）的微内核版：从零编写的 Rust 能力式微内核，运行在 QEMU 中。

本仓库自成一体，不依赖任何其他仓库。唯一的规格文件是 [`SPEC.md`](SPEC.md)，第一部分规定系统语义，第二部分规定平台实现。

## 给实现 agent

1. 先读 `SPEC.md` 的 §0，再通读全文。
2. 按 §18 的仓库布局组织代码。核心库、人的界面、iPhone 确认器、宿主机上的计算 worker 都在本仓库内实现。
3. §B4 的能力分配表就是安全规格，任何偏离都必须写进 `DECISIONS.md`。
4. B-4 之前先完成 TLS 技术验证（§B7）。
