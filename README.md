# smoothie_operator<<

## Hashes and versions

MD5 hashes: 

```
smoothie_operator : 79ee63a203b20124e5d7cf8cafd525a6
libc-2.31.so : 5898fac5d2680d0d8fefdadd632b7188
OS : Ubuntu 20.04 (docker sha256:450e066588f42ebe1551f3b1a535034b6aa46cd936fe7f2c6b0d72997ec61dbd)
```

## Description

This challenge incorporates an OOB heap write to corrupt heap metadata, creating a UAF by clobbering the `std::shared_ptr` struct. The challenge is a x86-64 ELF binary linked against glibc 2.31 (prior to the introduction of heap safe-linking in 2.32). This version is important for the exploit to work, as it relies on corrupting `__free_hook` and does not reveal/write masked pointer addresses. 

## Walkthrough

A detailed walkthrough of the vulnerabilities and (intended) exploitation strategy can be found [here](https://margin.re/2022/11/smoothie_operator/)
