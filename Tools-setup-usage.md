### 1. Pwn (Binary Exploitation)

**Goal:** Memory corruption, buffer overflows, ROP chains.

* **Essential Tools:**
  * **GDB + GEF:** Standard GDB is unusable for CTFs. You need GEF (GDB Enhanced Features) or Pwndbg to visualize the stack and registers.
  * **Pwntools:** The absolute standard Python library for writing exploit scripts.
  * **Checksec:** Checks binary protections (NX, Canary, PIE).
  * **ROPgadget:** Finds gadgets (small code snippets) for ROP chains.


* **Setup:**
 ```bash
 # Install GEF (GDB Extension)
 bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
 
 # Install Pwntools & ROPgadget
 mkdir -p ~/.venvs/ctf
 python3 -m venv ~/.venvs/ctf
 source ~/.venvs/ctf/bin/activate
 pip install pwntools ropgadget
 
 ```


* **How to use them (Workflow):**
 1. **Check protections:**
 ```bash
 checksec --file=vuln_binary
 # Look for "NX Disabled" (Shellcode possible) or "No Canary" (Overflow easy)
 
 ```
 
 
 2. **Find the crash offset:**
 Open GDB (`gdb ./vuln_binary`), run `pattern create 100`, paste the output into the program. When it crashes, use `pattern offset <value_in_EIP>` to find exactly how many bytes to pad.
 3. **Script the exploit (Pwntools):**
 ```python
 from pwn import *
 p = process('./vuln_binary') # or remote('ip', port)
 
 # Create payload: 64 'A's + address of 'win' function
 payload = b'A' * 64 + p64(0x08048456) 
 
 p.sendline(payload)
 p.interactive()
 
 ```





---

### 2. Web (Web Security)

**Goal:** SQL Injection, XSS, SSTI, IDOR.

* **Essential Tools:**
 * **Burp Suite (Community):** Use the "Repeater" tab religiously.
 * **FFUF:** Faster than Gobuster for directory brute-forcing.
 * **Sqlmap:** Automated SQL injection (good for verify, but learn manual first).
 * **HackBar (Browser Extension):** Quickly encode/decode payloads in your browser (Base64, URL encode).


* **Setup:**
 * **FFUF:** `sudo apt install ffuf`
 * **Wordlists:** Ensure `/usr/share/wordlists/` is populated (Rockyou, Dirb).


* **How to use them (Workflow):**
 1. **Fuzzing directories:**
 ```bash
 # Fuzz for hidden files using a common wordlist
 ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301
 
 ```


2. **Manual Testing (Burp Repeater):**
Right-click a request in Burp Proxy History -> "Send to Repeater". Change input fields to `' OR 1=1 --` to test for SQLi, or `{{7*7}}` to test for Server Side Template Injection (SSTI).



---

### 3. Cry (Cryptography)

**Goal:** Breaking weak encryption (RSA, XOR, Caesar).

* **Essential Tools:**
 * **RsaCtfTool:** Automates attacks on weak RSA keys (e.g., small prime numbers).
 * **Xortool:** Analyzes and breaks multi-byte XOR encryption.
 * **CyberChef:** (Run locally or use web).


* **Setup:**
```bash
# Install RsaCtfTool
git clone https://github.com/RsaCtfTool/RsaCtfTool.git
cd RsaCtfTool && pip3 install -r requirements.txt

```


* **How to use them (Workflow):**
 1. **Weak RSA:** If you are given a `public_key.pem` and `flag.enc`:
 ```bash
 python3 RsaCtfTool.py --publickey public_key.pem --uncipher flag.enc
 
 ```
 
 
 2. **XOR Analysis:** If you have a file that looks like garbage bytes:
 ```bash
 # Guesses the key length and the key itself
 xortool ciphertext.bin
 
 ```





---

### 4. Misc (Miscellaneous)

**Goal:** Forensics, Steganography, Jail Escaping, Network Analysis.

* **Essential Tools:**
 * **Wireshark:** Network packet analysis.
 * **Binwalk:** Extracting files hidden inside other files.
 * **Stegsolve:** Java tool for visualizing image bits (LSB steganography).
 * **ExifTool:** Metadata reader.


* **Setup:**
 * **Stegsolve:** Download the `.jar` file and run with `java -jar stegsolve.jar`.


* **How to use them (Workflow):**
 1. **Hidden Files:** Always run this on any file provided in Misc/Forensics:
 ```bash
 # -e extracts files automatically
 binwalk -e strange_image.jpg 
 
 ```


 2. **Network Flags:**
 Open `.pcap` in Wireshark. Filter by `http.request.method == "POST"` to see data being sent, or `tcp.stream eq 0` to follow the conversation stream.



---

### 5. Rev (Reverse Engineering)

**Goal:** Understanding compiled code without source.

* **Essential Tools:**
 * **Ghidra:** The industry standard free decompiler.
 * **Strings:** The "low hanging fruit" checker.
 * **Ltrace:** Traces library calls (like `strcmp`).


* **Setup:**
 * `sudo apt install ghidra` (requires JDK).


* **How to use them (Workflow):**
 1. **The "Lazy" Check:**
 ```bash
 strings ./binary | grep "CTF"
 
 ```


 2. **Dynamic Analysis:**
 Run the binary with `ltrace` to see what it compares your input against.
 ```bash
 ltrace ./bomb
 # Output might show: strcmp("MyInput", "SecretPassword")
 
 ```


 3. **Static Analysis (Ghidra):**
 Open the binary in Ghidra. Look for the `main` function. Double-click it to see the "Decompile" window (pseudo-C code). Look for `if (local_var == 0xdeadbeef)` to find the logic.



---

### Suggested First Step

To ensure your Pwn setup is correct (since it's the trickiest to configure), try running this simple check in your terminal to see if **Pwntools** is ready:

```bash
python3 -c "from pwn import *; print(cyclic(50))"

```

**Does that output a string of random characters?**
