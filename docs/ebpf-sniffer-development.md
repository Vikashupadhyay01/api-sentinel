\- Kernel: 7.2.15+kali-amd64



\## Installed Dependencies

\- Rust 1.100.0

\- Cargo 1.100.0

\- Clang 21.1.8

\- BPFTool 7.8.0

\- LLVM

\- libelf-dev

\- build-essential

\- Linux kernel headers



\## Kernel Verification

Successfully verified:



1\. Linux kernel headers.

2\. Kernel BTF availability at `/sys/kernel/btf/vmlinux`.

3\. TCP tracepoint availability: `inet\_sock\_set\_state`.

4\. Tracepoint fields:

&#x20;  - Source and destination ports.

&#x20;  - Source and destination addresses.

&#x20;  - Old and new TCP states.

&#x20;  - Network family and protocol.



\## Next Implementation Tasks

\- Configure Aya Rust eBPF framework.

\- Implement TCP socket state monitoring.

\- Develop Rust userspace event collector.

\- Test TCP event collection.

\- Perform API latency benchmarking.

\- Compare latency with the sniffer enabled and disabled.



\## Current Progress

Completed: Development environment preparation, dependency installation, kernel header verification, BTF verification and TCP tracepoint inspection.



Pending: Aya project generation, eBPF implementation, event collection and latency benchmarking.



\## Assigned Module

eBPF Network Sniffer and Latency Audit – API Sentinel.

