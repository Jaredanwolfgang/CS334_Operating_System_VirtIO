/*
    The virtio crypto is a virtual crypto device as well as a kind of virtual hardware accelerator 
    for virtual machines. 
    
    The encryption and decryption requests are placed in the data queue and handled by the real 
    crypto accelerators finally. 
    
    The second queue is the control queue used to create or destroy sessions for symmetric algorithms 
    and control some advanced features in the future. 
    
    The virtio crypto device provides the following crypto services: CIPHER, MAC, HASH, AEAD etc.
*/
