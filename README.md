# CS334 VirtIO Crypto Device

This is a simple implementation of a VirtIO crypto device. The device is a PCI device that can be used to encrypt and decrypt data. The device is implemented in QEMU.

The current TODO list is as follows:
- [x] Symmetric Algorithm
    - [x] Cipher
        - [x] Encryption
        - [x] Decryption
    - [x] Chain Algorithm
        - [x] Hash Algorithm
            - [x] Encryption
            - [x] Decryption
        - [x] MAC Algorithm
            - [x] Encryption
            - [x] Decryption
- [x] AKCIPHER Algorithm
    - [x] Encryption
    - [x] Decryption
    - [x] Sign
    - [x] Verify
- [x] Writing Test Cases
- [x] Asynchronous Request
- [x] User Call

## Introducing Asterinas

Asterinas is a _secure_, _fast_, and _general-purpose_ OS kernel
that provides _Linux-compatible_ ABI.
It can serve as a seamless replacement for Linux
while enhancing _memory safety_ and _developer friendliness_.

* Asterinas prioritizes memory safety
by employing Rust as its sole programming language
and limiting the use of _unsafe Rust_
to a clearly defined and minimal Trusted Computing Base (TCB).
This innovative approach,
known as [the framekernel architecture](https://asterinas.github.io/book/kernel/the-framekernel-architecture.html),
establishes Asterinas as a more secure and dependable kernel option.

* Asterinas surpasses Linux in terms of developer friendliness.
It empowers kernel developers to
(1) utilize the more productive Rust programming language,
(2) leverage a purpose-built toolkit called [OSDK](https://asterinas.github.io/book/osdk/guide/index.html) to streamline their workflows,
and (3) choose between releasing their kernel modules as open source
or keeping them proprietary,
thanks to the flexibility offered by [MPL](#License).

While the journey towards a production-grade OS kernel can be challenging,
we are steadfastly progressing towards our goal.
Currently, Asterinas only supports x86-64 VMs.
However, [our aim for 2024](https://asterinas.github.io/book/kernel/roadmap.html) is
to make Asterinas production-ready on x86-64 VMs.

## Getting Started

Get yourself an x86-64 Linux machine with Docker installed.
Follow the three simple steps below to get Asterinas up and running.

1. Download the latest source code.

```bash
git clone https://github.com/asterinas/asterinas
```

2. Run a Docker container as the development environment.

```bash
docker run -it --privileged --network=host --device=/dev/kvm -v $(pwd)/asterinas:/root/asterinas asterinas/asterinas:0.11.1
```

3. Inside the container, go to the project folder to build and run Asterinas.

```bash
make build
make run
```

If everything goes well, Asterinas is now up and running inside a VM.

## The Book

See [The Asterinas Book](https://asterinas.github.io/book/) to learn more about the project.

## License

Asterinas's source code and documentation primarily use the 
[Mozilla Public License (MPL), Version 2.0](https://github.com/asterinas/asterinas/blob/main/LICENSE-MPL).
Select components are under more permissive licenses,
detailed [here](https://github.com/asterinas/asterinas/blob/main/.licenserc.yaml). For the rationales behind the choice of MPL, see [here](https://asterinas.github.io/book/index.html#licensing).
