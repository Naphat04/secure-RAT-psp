# ระบบ Custom Cryptographic Handshake & Secure C2 Demo (Go)

โปรเจกต์นี้สร้างขึ้นเพื่อสาธิตและพิสูจน์เชิงประจักษ์ (Empirical Demo) ว่า **ทฤษฎีการแลกเปลี่ยนกุญแจลับด้วยการผสม Keys ที่แตกต่างกัน (Diffie-Hellman / ECDH)** สามารถนำมาใช้งานได้จริงในระดับโค้ด พร้อมทั้งแก้ไขช่องโหว่ด้านความปลอดภัยด้วย **HMAC Agent Authentication** และการเข้ารหัสอุโมงค์สื่อสารด้วย **AES-256-GCM**

---

## 📂 โครงสร้างของโปรเจกต์

```
test_security_psp/
├── pkg/
│   ├── crypto/
│   │   ├── ecdh.go          # X25519 Key Generation และคำนวณ Shared Secret (SSK)
│   │   ├── hmac.go          # HMAC-SHA256 ป้องกันเครื่องลูกปลอม (Constant-time verify)
│   │   ├── hkdf.go          # สกัด Session Key จาก Shared Secret
│   │   ├── aes_gcm.go       # เข้ารหัส/ถอดรหัส AES-256-GCM พร้อม Nonce 12 bytes
│   │   └── crypto_test.go   # Automated Unit Test ทดสอบทฤษฎีคณิตศาสตร์
│   └── protocol/
│       └── messages.go      # โครงสร้าง JSON ของ Handshake และ Encrypted Payload
├── cmd/
│   ├── keygen/main.go       # เครื่องมือสุ่มคู่กุญแจแม่ (ser_pri_key, ser_pub_key)
│   ├── server/main.go       # C2 Server (รับ WebSocket, ตรวจสอบ HMAC, สั่งการ)
│   └── agent/main.go        # Agent (สุ่ม Ephemeral Key, ยืนยันสิทธิ์, รับคำสั่ง)
├── server_keys.json         # ไฟล์เก็บกุญแจ Server
└── README.md                # เอกสารประกอบการพรีเซนต์
```

---

## 🚀 วิธีการทดสอบแบบเปิด 2 Terminal คู่กัน

### ขั้นตอนที่ 1: รัน Server (Terminal ที่ 1)
เปิด Terminal ที่ 1 แล้วรันคำสั่ง:
```powershell
go run ./cmd/server
```
หรือรันผ่านไฟล์ `.exe`:
```powershell
.\server.exe
```
*Server จะเริ่มฟังการเชื่อมต่อที่ `ws://localhost:8080/ws` และแสดง Public Key ของแม่ขึ้นมา*

---

### ขั้นตอนที่ 2: รัน Agent เชื่อมต่อปกติ (Terminal ที่ 2)
เปิด Terminal ที่ 2 (วางข้างๆ Terminal 1) แล้วรัน:
```powershell
go run ./cmd/agent
```
หรือรันผ่านไฟล์ `.exe`:
```powershell
.\agent.exe
```

#### 🔍 จุดที่ให้สังเกตและชี้ให้อาจารย์ดู:
1. **คีย์ลับ SSK ตรงกันเป๊ะ:** ดูค่า `🔑 SSK Fingerprint (SHA-256)` ในทั้งสองหน้าจอ จะเห็นว่าเป็นเลขเดียวกัน 64 ตัวอักษร ทั้งๆ ที่ Server ใช้ `ser_pri + cli_pub` และ Agent ใช้ `cli_pri + ser_pub`
2. **การสกัด Session Key:** ทั้งคู่รันผ่าน `HKDF-SHA256` ได้ `🛡️ Session Key Fingerprint` ตรงกัน
3. **ข้อความที่ส่งผ่านสายสัญญาณถูกเข้ารหัส:** ดูบรรทัด `[🔒 Wire Ciphertext]` จะเห็นว่าเป็นเลขสุ่มฐาน 16 (Hex) ที่คนดักฟังไม่มีทางอ่านออก แต่ทั้งสองฝั่งสามารถถอดรหัสออกมาเป็น `[🔓 Decrypted Plain]` ได้อย่างถูกต้อง

---

### ขั้นตอนที่ 3: สาธิตกรณีแฮกเกอร์ปลอมตัวเป็น Agent (Rogue Agent Demo)
ใน Terminal ที่ 2 ให้ลองรันด้วยโหมด `-rogue` (จำลองผู้ไม่หวังดีที่มี `ser_pub_key` แต่ไม่มี `agent_secret`):
```powershell
go run ./cmd/agent -rogue
```
หรือ:
```powershell
.\agent.exe -rogue
```

#### 🔍 สิ่งที่เกิดขึ้น:
* **ฝั่ง Agent:** จะขึ้นเตือน `[!] 🚨 HANDSHAKE REJECTED BY SERVER! (Invalid HMAC signature)`
* **ฝั่ง Server:** จะขึ้นเตือนสีแดงทันที `[!] 🚨 SECURITY ALERT: HMAC SIGNATURE MISMATCH! Rogue Agent blocked!` และตัดการเชื่อมต่อทันที
* **ประโยชน์:** พิสูจน์ให้อาจารย์เห็นว่าระบบมี **Mutual Identity Verification** ป้องกันไม่ให้ใครก็ตามนำ Public Key ของ Server ไปยิงเล่นหรือสแปมระบบได้

---

## 🧠 คำอธิบายเชิงวิชาการสำหรับตอบคำถามอาจารย์

### 1. ถาม: "ทำไมเครื่องแม่กับเครื่องลูกถึงคำนวณได้คีย์ SSK ตัวเดียวกัน ทั้งๆ ที่ใช้คีย์คนละคู่?"
> **ตอบ:** "ระบบนี้ใช้หลักการ **Elliptic-Curve Diffie-Hellman (ECDH)** บนเส้นโค้ง **Curve25519 (X25519)** ครับ 
> โดยจุดสาธารณะคำนวณจาก $A = a \cdot G$ และ $B = b \cdot G$
> เมื่อฝั่งแม่นำ Public ของลูก ($B$) มาคูณกับ Private ของตนเอง ($a$) จะได้ $a \cdot (b \cdot G) = (a \cdot b) \cdot G$
> และเมื่อฝั่งลูกนำ Public ของแม่ ($A$) มาคูณกับ Private ของตนเอง ($b$) จะได้ $b \cdot (a \cdot G) = (a \cdot b) \cdot G$
> ผลลัพธ์ทางคณิตศาสตร์จึงได้พิกัดบนเส้นโค้งเดียวกันเป๊ะ โดยไม่ต้องส่ง Private Key ข้ามเน็ตเลยครับ"

### 2. ถาม: "ถ้าคนดักฟังบันทึก Traffic เก็บไว้ แล้ววันข้างหน้า Server โดนขโมย ser_pri_key ข้อมูลในอดีตจะหลุดไหม?"
> **ตอบ:** "ไม่หลุดครับ เพราะระบบเรามีคุณสมบัติ **Perfect Forward Secrecy (PFS)** โดยเครื่องลูกจะสุ่มกุญแจ `cli_pri_key` และ `cli_pub_key` ใหม่ทุกครั้งที่ต่อเชื่อม (Ephemeral Key) และทิ้งคีย์ทันทีเมื่อจบ Session ทำให้แม้กุญแจแม่ในอนาคตจะหลุด ก็ไม่สามารถคำนวณย้อนหลังได้เพราะไม่มี Ephemeral Private Key ของลูกในอดีตครับ"

### 3. ถาม: "ถ้าใครเอา Public Key ของ Server ไปเขียน Agent เองเพื่อยิงกวน Server จะกันยังไง?"
> **ตอบ:** "เราเสริมชั้น **HMAC-SHA256 (Hash-based Message Authentication Code)** โดยใช้ `agent_secret` ที่เครื่องลูกได้รับตั้งแต่ขั้นตอนการลงทะเบียน (Enrollment) มาเซ็นกำกับกุญแจสาธารณะของลูกและ Timestamp ทำให้ Server สามารถตรวจสอบสิทธิ์และป้องกัน Replay Attack ได้ก่อนที่จะยอมคำนวณคีย์ ECDH ครับ"

### 4. ถาม: "ทำไมต้องมี HKDF คั่นกลาง ไม่เอาผลลัพธ์ ECDH ไปใช้เป็น AES Key เลย?"
> **ตอบ:** "เพราะผลลัพธ์จากการทำ ECDH มีการกระจายตัวของบิต (Entropy Distribution) ที่ไม่สม่ำเสมอตามมาตรฐานการเข้ารหัสแบบสมมาตร เราจึงต้องใช้ **HKDF (RFC 5869)** เพื่อสกัด (Extract) และขยาย (Expand) ให้ได้กุญแจความยาว 256 บิตที่มี Pseudo-randomness สูงสุดสำหรับ **AES-256-GCM** ครับ"

---

## 📖 ผ่าลึกสิ่งที่เกิดขึ้นใน 2 Terminal (ถอดรหัสเป็นภาษาคน & Interactive ละเอียดยิบ)

ส่วนนี้เขียนขึ้นเพื่อให้คุณใช้ซ้อมอ่าน ทำความเข้าใจ และอธิบายให้อาจารย์ฟังทีละบรรทัดว่า บนหน้าจอ Terminal ซ้าย (Server) กับ ขวา (Agent) มันกำลังคุยอะไรกันอยู่ และมีปฏิสัมพันธ์ (Interactive) กันอย่างไร

```
+------------------------------------+             +------------------------------------+
|   🖥️ TERMINAL 1: C2 SERVER (แม่)    |             |    💻 TERMINAL 2: AGENT (ลูก)      |
+------------------------------------+             +------------------------------------+
| [1] เปิดประตูบ้านรอ (Port 8080)    | <=========== | [1] วิ่งมาเคาะประตูเชื่อมต่อ         |
| [2] ได้รับพัสดุ Handshake          | <----------- | [2] สุ่มคีย์ลูก + ประทับตรา HMAC ส่ง |
| [3] ตรวจตรายาง HMAC -> ถูกต้อง!   |             |                                    |
| [4] คำนวณ SSK ในใจ                 |             | [3] คำนวณ SSK ในใจ                 |
|     (ser_pri + cli_pub)            |             |     (cli_pri + ser_pub)            |
|     => ได้รหัสตู้เซฟ: 9468d4...    |             |     => ได้รหัสตู้เซฟ: 9468d4...    |
| [5] แตกเป็น Session Key: 4d97a3... |             | [4] แตกเป็น Session Key: 4d97a3... |
|                                    |             |                                    |
| [6] ล็อกกล่องส่งคำสั่งสแกนไวรัส   | -----------> | [5] ไขกล่องอ่านคำสั่งสแกนไวรัส     |
| [7] ไขกล่องอ่านผลลัพธ์ Clean       | <----------- | [6] สั่ง Defender เสร็จ ล็อกกล่องส่ง |
+------------------------------------+             +------------------------------------+
```

---

### 🎬 ฉากที่ 1: ขั้นเริ่มเปิดโปรแกรม (Startup & Network Connection)

#### ฝั่ง Server (Terminal 1) แสดง:
```text
================================================================
        C2 MANAGEMENT SERVER (ECDH + HMAC + AES-GCM)            
================================================================
[+] Server Public Key (ser_pub_key):
    dc003f6adbbab9cdd9106acd4ca1095e08d1a4dda0553cdaa054a01f9c87363b
[+] Registered Agents in Database: 2 agents
    - AGENT-001 (Secret: [ENROLLED])
    - AGENT-002 (Secret: [ENROLLED])
----------------------------------------------------------------
[*] Starting WebSocket listener on :8080...
[✓] Server is ready! Waiting for Agent connections at ws://localhost:8080/ws
```
* **ภาษาคน:** เครื่องแม่เปิดเครื่องขึ้นมา โหลดกุญแจสาธารณะของตัวเองเบอร์ `dc003f...` แล้วเปิดสมุดบัญชีดูว่า *"มีเครื่องลูกที่ได้รับอนุญาต 2 ตัวนะ คือ AGENT-001 กับ AGENT-002"* จากนั้นก็เปิดประตูบ้านรอไว้ที่พอร์ต 8080

#### ฝั่ง Agent (Terminal 2) แสดง:
```text
================================================================
               GO AGENT CLIENT (C2 ENDPOINT)                    
================================================================
[+] Hardcoded Server Public Key (ser_pub_key):
    dc003f6adbbab9cdd9106acd4ca1095e08d1a4dda0553cdaa054a01f9c87363b
[+] Agent Identity: AGENT-001
[+] Valid Enrollment Secret Loaded
----------------------------------------------------------------
[*] Connecting to C2 Server at ws://localhost:8080/ws...
[✓] TCP & WebSocket connection established.
```
* **ภาษาคน:** เครื่องลูกเปิดโปรแกรมขึ้นมา ในตัวเครื่องลูกมีแม่กุญแจของแม่ฝังไว้แต่แรกแล้ว (`dc003f...`) และลูกจำได้ว่าตัวเองชื่อ `AGENT-001` จากนั้นลูกก็วิ่งออกเน็ตไปเคาะประตูบ้านแม่ที่ `ws://localhost:8080/ws`

🔗 **จุด Interactive ระหว่างกัน:** 
ทันทีที่ลูกกดเชื่อมต่อ หน้าจอแม่จะกระพริบรับการเชื่อมต่อทันที:
`[+] [CONNECT] New connection established from [::1]:49847` (แม่รู้แล้วว่ามีคนมาต่อ)

---

### 🤝 ฉากที่ 2: ขั้นตอนจับมือแลกคีย์ (The Cryptographic Handshake)
*นี่คือช่วงที่สำคัญที่สุดทางคณิตศาสตร์และความปลอดภัย:*

#### ขั้นที่ 2.1: ลูกสร้างกุญแจชั่วคราวและประทับตรายาง
**หน้าจอ Agent แสดง:**
```text
[*] [1] Generating Ephemeral X25519 Keypair for this session...
    Client Ephemeral Public Key (cli_pub_key):
    1674356fd66dc006ef225526748e3a4e1b40b7522a037b8874a3b0a016c4510a
[*] [2] Creating HMAC-SHA256 Signature with Agent Secret...
    Signed Data: AgentID + cli_pub_key + Timestamp
    Signature  : ae60e601bbb53e1d22b78c7587723b4bf92d2e55be643a48f0d68ec88474a6f2
[*] [3] Transmitting HandshakeRequest over WebSocket...
```
* **ภาษาคน:**
  1. ลูกจะไม่ใช้กุญแจเก่าเลย ลูกสุ่มคู่กุญแจใหม่สดๆ สำหรับรอบนี้ขึ้นมา ได้กุญแจสาธารณะเบอร์ `167435...` (เพื่อความปลอดภัยแบบ Perfect Forward Secrecy)
  2. ลูกเอาชื่อตัวเอง (`AGENT-001`) + กุญแจใหม่ (`167435...`) + เวลาปัจจุบัน ไปประทับตรายางลับด้วย `agent_secret` ออกมาเป็นลายเซ็น `ae60e6...`
  3. ส่งก้อนข้อมูลนี้ข้ามเน็ตไปให้แม่

#### ขั้นที่ 2.2: แม่ตรวจสอบตรายาง (Authentication Check)
**หน้าจอ Server แสดง:**
```text
[1] Handshake received from AgentID: AGENT-001
    Client Public Key (cli_pub_key): 1674356fd66dc006ef225526748e3a4e1b40b7522a037b8874a3b0a016c4510a
    Client Timestamp               : 1789053542
    Client Signature (HMAC)        : ae60e601bbb53e1d22b78c7587723b4bf92d2e55be643a48f0d68ec88474a6f2

[✓] [2] HMAC Verification: PASSED (Authentic Agent Identity Confirmed)
```
* **ภาษาคน:** แม่รับซองจดหมายมา แกะดูพบว่าเป็น `AGENT-001` ส่งกุญแจ `167435...` มาพร้อมลายเซ็น `ae60e6...` แม่จึงเดินไปเปิดตู้เซฟหยิบ `agent_secret` ของ AGENT-001 ออกมาลองคำนวณดู พบว่า **ตรายางตรงกันเป๊ะ!** แปลว่า *"นี่คือลูกตัวจริงที่ลงทะเบียนไว้ ไม่ใช่แฮกเกอร์ปลอมตัวมา"*

#### ขั้นที่ 2.3: คำนวณรหัสตู้เซฟร่วมกันในใจ (จุดพิสูจน์ทฤษฎีที่คุณคิด!)
**หน้าจอ Server แสดง:**
```text
[✓] [3] ECDH Shared Secret (SSK) Computed!
    Formula: ECDH(ser_pri_key, cli_pub_key)
    🔑 SSK Fingerprint (SHA-256)   : 9468d4cbb8c083c4342d5956a4814430fc4ea0f46c22f2d49a5c9d3a988c8c0f
```
**หน้าจอ Agent แสดง:**
```text
[✓] [4] ECDH Shared Secret (SSK) Computed on Agent!
    Formula: ECDH(cli_pri_key, ser_pub_key)
    🔑 SSK Fingerprint (SHA-256)   : 9468d4cbb8c083c4342d5956a4814430fc4ea0f46c22f2d49a5c9d3a988c8c0f
```

🔗 **จุด Interactive มหัศจรรย์ทางคณิตศาสตร์:**
* สังเกตที่บรรทัด **`🔑 SSK Fingerprint`**: ทั้งหน้าจอ Server และ Agent ขึ้นเลขเดียวกันคือ:
  `9468d4cbb8c083c4342d5956a4814430fc4ea0f46c22f2d49a5c9d3a988c8c0f`
* **ทำไมถึงมหัศจรรย์?** เพราะแม่ใช้ `กุญแจลับแม่ + กุญแจสาธารณะลูก` ส่วนลูกใช้ `กุญแจลับลูก + กุญแจสาธารณะแม่` แต่ปลายทางได้เลขเดียวกันเป๊ะ **โดยที่ทั้งคู่ไม่เคยส่งเลข `9468d4...` ข้ามสายสัญญาณหากันเลย!** คนดักฟังต่อให้ดักฟังสัญญาณได้ 100% ก็ไม่มีวันรู้เลขนี้!

#### ขั้นที่ 2.4: แตกเป็น Session Key สำหรับเข้ารหัส AES
**ทั้งสองหน้าจอแสดง:**
```text
[✓] Derived Session Key via HKDF-SHA256!
    🛡️ Session Key Fingerprint     : 4d97a32405c83761346ed3eb350870695efbb917f7a56fa695b61351330fb083
```
* **ภาษาคน:** ทั้งคู่เอารหัสตู้เซฟไปผ่านเครื่องสกัด (HKDF) เพื่อทำเป็นลูกกุญแจความยาว 32 bytes (256 บิต) ได้กุญแจรหัส `4d97a3...` ตรงกันทั้งสองฝั่ง พร้อมใช้ล็อกกล่องข้อความแล้ว

---

### 📦 ฉากที่ 3: การรับส่งคำสั่งจริง (Encrypted Communication)

#### คำสั่งที่ 1: สั่งสแกนไวรัส (SCAN_VIRUS)
1. **Server สั่งงาน:**
   ```text
   📤 [SENT TO AGENT]
       [🔓 Action Planned]  : SCAN_VIRUS (ID: CMD-101)
       [🔒 Sent on Wire]   : 81c0885c579dd70c162957123f1bdeb2... (encrypted AES-256-GCM)
   ```
   * *ภาษาคน:* แม่เตรียมสั่ง `SCAN_VIRUS` แต่ไม่ส่งตรงๆ แม่เอากุญแจ `4d97a3...` ล็อกข้อความจนกลายเป็นตัวเลขยึกยือฐาน 16 (`81c088...`) แล้วปล่อยลงสายเน็ต

2. **Agent รับไปไข:**
   ```text
   📥 [COMMAND RECEIVED]
       [🔒 Wire Ciphertext] : 81c0885c579dd70c162957123f1bdeb2... (length: 260 chars)
       [🔓 Decrypted Plain] : Action=SCAN_VIRUS (ID=CMD-101)
   ```
   * *ภาษาคน:* ลูกได้รับกล่องล็อกรหัส `81c088...` ลูกเอากุญแจของตัวเองไขออกมา อ่านรู้เรื่องทันทีว่า *"แม่สั่งให้ตรวจไวรัสนี่นา"*

3. **Agent รายงานผลกลับ:**
   ```text
   📤 [ENCRYPTED RESPONSE SENT]
       [🔓 Plain Result]    : Windows Defender Scan Completed: Status Code 0 (ไม่พบไวรัส / Clean)
       [🔒 Sent on Wire]    : dcb80abff384d0da95bc4e604a960ba5... (AES-256-GCM)
   ```
   * *ภาษาคน:* ลูกเรียกใช้ Defender เสร็จ ได้ผลว่าปลอดภัย Status Code 0 จึงเอากุญแจล็อกรายงานผลกลายเป็นตัวเลขยึกยือ `dcb80a...` ส่งกลับหาแม่

4. **Server รับรายงานผล:**
   ```text
   📥 [RECV FROM AGENT]
       [🔒 Wire Ciphertext] : dcb80abff384d0da95bc4e604a960ba5... (length: 532 chars)
       [🔓 Decrypted Plain] : Status=SUCCESS, CmdID=CMD-101
       [📄 Output]           : Windows Defender Scan Completed: Status Code 0 (ไม่พบไวรัส / Clean)
   ```
   * *ภาษาคน:* แม่ได้รับกล่อง `dcb80a...` มาไขกุญแจอ่าน ก็รู้ผลทันทีว่าลูกตรวจไวรัสเสร็จแล้วและไม่พบภัยคุกคาม

*(คำสั่งต่อไปอย่าง `GET_PROCESSES` และ `SYSTEM_INFO` ก็จะทำงานแบบเข้ารหัสสองทางแบบนี้ทุกๆ 3 วินาทีสม่ำเสมอ)*

---

### 🦹‍♂️ ฉากที่ 4: สาธิตกรณีแฮกเกอร์พยายามปลอมตัว (Rogue Agent Simulation)

เมื่อรัน Terminal 2 ด้วยคำสั่ง:
```powershell
.\agent.exe -rogue
```

#### หน้าจอ Agent (แฮกเกอร์) แสดง:
```text
🚨 SIMULATING ROGUE AGENT (ATTACKER / SPOOFING TEST)
[+] Hardcoded Server Public Key (ser_pub_key): dc003f...
[+] Agent Identity: AGENT-001
[!] Using INVALID/SPOOFED Secret: attacker-fake-secret-99999
...
[!] 🚨 HANDSHAKE REJECTED BY SERVER!
    Server Reason: Invalid HMAC signature. Rogue Agent blocked!
[✓] DEMO PROOF: The Server successfully blocked the Rogue Agent!
```

#### หน้าจอ Server (ระบบป้องกัน) แสดง:
```text
[+] [CONNECT] New connection established from [::1]:60584
----------------------------------------------------------------
                   🤝 HANDSHAKE VERIFICATION                   
----------------------------------------------------------------
[1] Handshake received from AgentID: AGENT-001
    Client Public Key (cli_pub_key): b1e8b8618e50946bc23d84ba2dfcd9f53...
    Client Timestamp               : 1789053571
    Client Signature (HMAC)        : d46e44af52c40ff9029ef0cdbf3ddf525...

[!] 🚨 SECURITY ALERT: HMAC SIGNATURE MISMATCH!
    Someone is trying to spoof Agent ID or injected a fake Public Key!
    Connection is terminated immediately.
```

🔗 **Interactive ที่เกิดขึ้น:**
* แฮกเกอร์มี `ser_pub_key` ของแม่จริง และอ้างชื่อว่าตัวเองคือ `AGENT-001`
* แต่แฮกเกอร์ **ไม่มี `agent_secret` ตัวจริง** ของเครื่องลูก ทำให้ปั๊มลายเซ็น HMAC ออกมาผิด
* **แม่ตรวจเจอลายเซ็นเก๊:** แม่ตัดสัญญาณการเชื่อมต่อทันที (Drop Connection) ไม่ยอมเสียเวลาไปคำนวณคีย์ ECDH ให้แฮกเกอร์ และแฮกเกอร์ก็ถูกเตะออกจากระบบทันที!

---

## 📦 โครงสร้าง Payload ของการส่งข้อความแบบ AES-256-GCM (แบบผ่าละเอียด)

เมื่อผ่านขั้นตอน Handshake เรียบร้อยแล้ว ทุกข้อความที่รับ-ส่งระหว่าง Server กับ Agent (ทั้งคำสั่งและรายงานผล) จะถูกห่อและส่งผ่าน WebSocket ในรูปแบบนี้:

### 1. ซองจดหมายรอบนอก (Outer Envelope: JSON ที่วิ่งผ่าน WebSocket)
```json
{
  "type": "COMMAND",
  "sequence": 1,
  "payload_hex": "81c0885c579dd70c162957123f1bdeb2...4e7a2b91c80f34d19a2e6f11bc04a899"
}
```
* **`type`**: ชนิดของข้อความ (`COMMAND` สำหรับคำสั่งจากแม่, `RESPONSE` สำหรับคำตอบจากลูก, `HEARTBEAT` สำหรับเช็กสถานะ)
* **`sequence`**: เลขลำดับข้อความ (1, 2, 3...) เพิ่มขึ้นเรื่อยๆ เพื่อป้องกันข้อความสลับคิว หรือป้องกันการดักข้อความเก่ามาส่งซ้ำ (Replay Attack)
* **`payload_hex`**: ก้อนข้อมูลไบนารีที่ถูกเข้ารหัสด้วย AES-256-GCM แล้วแปลงเป็นรหัสฐาน 16 (Hex) เพื่อความสะดวกในการส่งผ่าน WebSocket

---

### 2. ผ่าไส้ในของ `payload_hex` (โครงสร้างไบนารี AES-GCM)
ก้อนรหัสฐาน 16 ใน `payload_hex` เมื่อแกะออกมาเป็นไบต์ จะประกอบด้วย **3 ส่วนสำคัญที่เรียงต่อกัน** ดังนี้:

```
+--------------------------+-----------------------------------+--------------------------+
|  ส่วนที่ 1: Nonce (IV)     |  ส่วนที่ 2: Ciphertext            |  ส่วนที่ 3: Auth Tag     |
+--------------------------+-----------------------------------+--------------------------+
|  • ความยาว: 12 ไบต์       |  • ความยาว: ตามขนาดข้อความ         |  • ความยาว: 16 ไบต์      |
|    (24 ตัวอักษร Hex)     |    (ตัวคำสั่งที่ถูกสับเละแล้ว)         |    (32 ตัวอักษร Hex)     |
|  • สุ่มใหม่ทุกรอบ         |  • คนดักฟังอ่านไม่ออก               |  • สติกเกอร์นิรภัยกันแกะ   |
+--------------------------+-----------------------------------+--------------------------+
```

#### ตัวอย่างการแยกชิ้นส่วนของจริง (จากใน Terminal):
สมมุติว่า Server ส่ง `payload_hex` ก้อนนี้:
`81c0885c579dd70c16295712` `3f1bdeb2ca8892...` `4e7a2b91c80f34d19a2e6f11bc04a899`

1. **`81c0885c579dd70c16295712` (24 ตัวแรก):** คือ **Nonce** ที่สุ่มขึ้นมาใหม่ในวินาทีนั้น เพื่อให้ข้อความหน้าตาเปลี่ยนไปเรื่อยๆ
2. **`3f1bdeb2ca8892...` (ก้อนตรงกลาง):** คือ **Ciphertext** เนื้อหาคำสั่งที่ถูกล็อกไว้ด้วย Session Key
3. **`4e7a2b91c80f34d19a2e6f11bc04a899` (32 ตัวท้าย):** คือ **Auth Tag** สติกเกอร์นิรภัยที่คอยตรวจจับว่ามีใครแอบแก้ไขข้อมูลระหว่างทางหรือไม่

---

### 3. เนื้อหาแท้จริงข้างในหลังถอดรหัส (Decrypted Plaintext JSON)
เมื่อปลายทางนำ `Session Key` มาไข `payload_hex` ผ่านฟังก์ชัน `crypto.Decrypt()` จะได้ข้อมูลดิบ JSON ที่อ่านเข้าใจได้ทันที:

#### ก. ขาไป (Server สั่ง Agent):
```json
{
  "command_id": "CMD-101",
  "action": "SCAN_VIRUS",
  "parameters": {
    "scan_type": "quick",
    "target": "C:\\Users"
  }
}
```

#### ข. ขากลับ (Agent ตอบกลับ Server):
```json
{
  "command_id": "CMD-101",
  "status": "SUCCESS",
  "output": "Windows Defender Scan Completed: Status Code 0 (ไม่พบไวรัส / Clean)",
  "details": {
    "engine": "MpCmdRun.exe",
    "exit_code": 0,
    "scan_type": "Quick Scan",
    "time_taken": "1.84s"
  }
}
```

---

### 🛡️ สรุปจุดปลอดภัยของ Payload ชุดนี้ (สำหรับตอบอาจารย์):
1. **คนดักฟังเห็นอะไร?** $\rightarrow$ เห็นแค่ JSON Envelope ที่มีตัวเลขยึกยือใน `payload_hex` คนดักฟังไม่มีทางรู้เลยว่าเป็นคำสั่งอะไร
2. **ถ้าแฮกเกอร์แอบแก้ตัวเลขใน `payload_hex`?** $\rightarrow$ ฟังก์ชัน `gcm.Open()` จะตรวจพบว่า Auth Tag ไม่ตรง และฟ้อง `message authentication failed` ทันที ปฏิเสธการทำงาน ไม่เปิดอ่านเด็ดขาด
3. **ถ้าส่งคำสั่งเดิมซ้ำ?** $\rightarrow$ ตัว `Nonce` ที่สุ่มใหม่ 12 ไบต์จะทำให้ก้อน `payload_hex` หน้าตาเปลี่ยนไปทุกครั้ง คนดักฟังไม่มีทางเดาทางได้เลย
"# secure-RAT-psp" 
