# CS334 VirtIO Crypto Device

This is a simple implementation of a VirtIO crypto device. The device is a PCI device that can be used to encrypt and decrypt data. The device is implemented in QEMU.

The current TODO list is as follows:
- [ ] Symmetric Algorithm
    - [x] Cipher
        - [x] Encryption
        - [x] Decryption
    - [ ] Chain Algorithm
        - [ ] Hash Algorithm
            - [ ] Encryption
            - [ ] Decryption
        - [ ] MAC Algorithm
            - [ ] Encryption
            - [ ] Decryption
- [ ] AKCIPHER Algorithm
    - [ ] Encryption
    - [ ] Decryption
    - [ ] Sign
    - [ ] Verify
- [ ] Writing Test Cases