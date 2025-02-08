# 📡 Network Analyzer [School Project]

## ✅ TODO List

Legend:
- ✅ = Tested and functional
- 🟨 = Not tested, functional
- 🟥 = Tested, not functional

### 🏷️ Capture
- [x] Packet capture ✅

### 📊 Analysis
#### 📌 Protocols
- [x] Ethernet ✅
- [x] IPv4 ✅
- [x] IPv6 ✅
- [x] UDP ✅
- [x] TCP ✅
- [x] ARP ✅
- [x] ICMP ✅

#### 🌐 Applications
- [x] DHCP ✅
- [x] DNS ✅
- [x] HTTP ✅
- [x] FTP ✅
- [x] SMTP ✅ ~
- [x] Telnet ✅
- [x] LDAP ✅ ~
- [x] POP ✅
- [x] IMAP ✅ ~

### ⚙️ Options
- [x] `-i` ✅
- [x] `-o` ✅
- [ ] `-f`
- [x] `-v` ✅

---

## 📖 Project Description

### 🔍 Network Analyzer

This project implements a simple network analyzer.

The `Makefile` is provided to compile the code. Once compiled, the executable can be found in the `bin/` directory.

### 🏃 Execution Modes
The program can be executed in different ways:

1. **Without a capture file**  
   - It analyzes predefined frames and displays the results in a simulation mode.  
   - This mode was initially created for testing but was retained as it demonstrates all the supported protocols.

2. **With the `-v` option (verbosity)**  
   - Controls the level of detail in the displayed results.  
   - By default, verbosity is set to maximum (`3`).  
   - Three levels are available (`1-3`).  
   - Compatible with or without a capture file.

3. **With the `-i [interface]` option (Live analysis)**  
   - Captures and analyzes all frames passing through the specified interface.

4. **With the `-o [output-file]` option (Offline analysis)**  
   - Analyzes frames stored in a `.pcap` file (e.g., generated with `tcpdump`).  
   - A test file is available in the `input/` directory.

### 📜 Results
- Results are displayed in the terminal.
- A `trame.txt` file is generated containing the raw frame data.

### 📚 Documentation
A Doxygen-generated documentation is available. To generate and open it:

```sh
doxygen Doxyfile
xdg-open docs/html/index.html
