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
