# Paper Lantern

## 1. Thông tin bài

- **Category:** Pwn
- **Challenge:** Paper Lantern
- **Target:** `178.105.199.41:20000`
- **Bug chính:** CRT-RSA fault attack
- **Kết quả:** Solved

---

## 2. Recon ban đầu

Đầu tiên mình kiểm tra thư mục đề bài:

```bash
ls -la
file *
```

Trong thư mục có các file đáng chú ý như:

```text
paper_lantern
capsule.py
public_params.json
```

Mình thử kiểm tra strings để xem trong binary có gì thú vị:

```bash
strings paper_lantern | grep -i flag
strings paper_lantern | grep -i slopped
```

Kết quả thấy có đường dẫn:

```text
/app/flag.txt
```

Lúc này mình hiểu flag có khả năng nằm trên server, không phải flag nằm sẵn trong file local.

![Recon files](./assets/1.png)

---

## 3. Đọc file `capsule.py`

Khi đọc `capsule.py`, mình thấy bài này không phải kiểu nhập text bình thường rồi buffer overflow đơn giản.

Service dùng một protocol riêng với các frame như:

```python
FT_HELLO = 0x10
FT_ACK_STRICT = 0x12
FT_INFO = 0x13
FT_NEWCAP = 0x20
FT_APPEND = 0x21
FT_SIGN = 0x22
FT_COMMENT = 0x23
FT_RUN = 0x24
```

Ý nghĩa mình hiểu được:

| Frame | Ý nghĩa |
|---|---|
| `FT_HELLO` | Bắt tay với server |
| `FT_ACK_STRICT` | Xác nhận strict mode |
| `FT_INFO` | Lấy thông tin public parameters |
| `FT_NEWCAP` | Tạo capsule mới |
| `FT_APPEND` | Thêm record/opcode vào capsule |
| `FT_SIGN` | Xin chữ ký cho capsule |
| `FT_COMMENT` | Gửi comment/replay data |
| `FT_RUN` | Chạy capsule với chữ ký |

Server cũng trả về các response type:

```python
RT_OK   = 0x80
RT_ERR  = 0x81
RT_MODE = 0x82
RT_SIG  = 0x83
RT_OUT  = 0x84
RT_INFO = 0x85
```

---

## 4. Hiểu custom protocol

Trong `capsule.py`, hàm gửi frame có dạng:

```python
header = struct.pack("<BBH", ftype, seq, len(payload))
```

Format này nghĩa là mỗi frame có cấu trúc:

```text
1 byte  ftype
1 byte  seq
2 bytes length
payload
```

Trong đó:

- `ftype`: loại frame, ví dụ `FT_SIGN`, `FT_RUN`
- `seq`: sequence number
- `length`: độ dài payload
- `payload`: dữ liệu thật gửi lên server

Ví dụ nếu gửi `FT_SIGN` với payload rỗng, length sẽ là `0`.

Nếu có ảnh protocol, chèn ở đây:

![Protocol frame](./assets/2)

---

## 5. Đọc `public_params.json`

Tiếp theo mình đọc file public params:

```bash
cat public_params.json
```

Các dòng quan trọng:

```text
scheme: crt-rsa-fdh
e: 65537
signature_size: 64
relay_buf: 72
comment_braid_max: 32
```

Ở đây có vài điểm đáng chú ý:

- `crt-rsa-fdh`: bài dùng RSA signature, có CRT optimization và Full Domain Hash.
- `e = 65537`: public exponent rất phổ biến trong RSA.
- `signature_size = 64`: chữ ký dài 64 bytes.
- `relay_buf = 72`: có một buffer liên quan tới comment/replay dài 72 bytes.

Ban đầu mình chưa biết `relay_buf` dùng để làm gì, nhưng con số 72 khá đáng nghi vì nó giống một vùng buffer có thể bị ghi vượt biên.

---

## 6. Thử tạo safe capsule

Trước khi khai thác, mình viết script test protocol để kiểm tra server hoạt động đúng như mình hiểu không.

Ý tưởng:

```text
TEXT("A") + HALT
```

Tức là tạo một capsule an toàn, chỉ in chữ `A` rồi dừng.

Script dùng các bước:

1. Handshake với server.
2. Gửi `FT_NEWCAP`.
3. Gửi capsule an toàn bằng `FT_APPEND`.
4. Gửi `FT_SIGN`.
5. Nhận chữ ký hợp lệ từ server.

Chạy script:

```bash
python3 scripts/01_test_safe_signature.py 178.105.199.41 20000
```

Nếu thành công, server trả về `RT_SIG` với chữ ký dài 64 bytes.

Điều này xác nhận:

- Protocol mình hiểu là đúng.
- Capsule hợp lệ có thể được server ký.
- `FT_SIGN` chỉ ký chương trình an toàn.

---

## 7. Tìm unsafe opcode

Khi xem strings trong binary, mình thấy có các chuỗi rất đáng chú ý:

```text
unsafe opcode
bad opcode
/app/flag.txt
```

Điều này gợi ý có một opcode nào đó bị cấm khi ký, nhưng có thể vẫn tồn tại trong VM.

Sau khi thử, mình chú ý tới opcode:

```text
0x7f
```

Khi tạo capsule có opcode `0x7f` rồi xin chữ ký, server trả về:

```text
unsafe opcode
```

Ví dụ capsule:

```text
7f 03
```

Trong đó:

- `0x7f`: opcode nghi là opcode in flag
- `0x03`: halt

Server không cho ký capsule này vì nó chứa unsafe opcode.

Nếu có ảnh unsafe opcode, chèn ở đây:

![Unsafe opcode](./assets/3.png)

---

## 8. Vấn đề chính

Đến đây mình có tình huống như sau:

```text
Safe capsule        -> server cho ký
Unsafe opcode 0x7f  -> server không cho ký
```

Nhưng nếu mình có thể tự tạo chữ ký hợp lệ cho unsafe capsule, server sẽ tin rằng capsule hợp lệ và chạy nó.

Vậy mục tiêu trở thành:

```text
Làm sao lấy được RSA private key d?
```

---

## 9. Nhắc lại RSA

RSA có public key:

```text
(n, e)
```

Và private key:

```text
d
```

Khi ký:

```text
signature = message^d mod n
```

Khi verify:

```text
message = signature^e mod n
```

Server giữ private key `d`.

Mình chỉ biết public key `(n, e)`, nên bình thường không thể tự ký được.

Muốn tính được `d`, mình cần biết `p` và `q` vì:

```text
n = p * q
phi = (p - 1) * (q - 1)
d = e^-1 mod phi
```

Vậy bài toán trở thành:

```text
Làm sao factor được n để lấy p và q?
```

---

## 10. CRT-RSA là gì?

Trong `public_params.json`, scheme là:

```text
crt-rsa-fdh
```

RSA thường ký như sau:

```text
s = m^d mod n
```

Nhưng RSA-CRT tối ưu bằng cách tách thành hai nhánh:

```text
sp = m^dp mod p
sq = m^dq mod q
```

Sau đó ghép `sp` và `sq` lại bằng CRT để tạo chữ ký cuối cùng.

Cách này nhanh hơn, nhưng nếu một nhánh bị lỗi thì có thể làm lộ `p` hoặc `q`.

---

## 11. CRT fault attack

Giả sử server tạo ra một chữ ký lỗi.

Nếu nhánh modulo `p` bị lỗi nhưng nhánh modulo `q` vẫn đúng, thì chữ ký lỗi và chữ ký đúng sẽ giống nhau theo modulo `q`.

Nói cách khác:

```text
good_sig ≡ faulty_sig mod q
```

Suy ra:

```text
good_sig - faulty_sig chia hết cho q
```

Vì:

```text
n = p * q
```

Nên ta có thể tính:

```text
g = gcd(good_sig - faulty_sig, n)
```

Nếu `g` khác `1` và khác `n`, thì `g` chính là một trong hai thừa số `p` hoặc `q`.

Trong script mình dùng dạng kiểm tra theo message:

```python
diff = (pow(faulty_sig, e, n) - safe_m) % n
p = gcd(diff, n)
q = n // p
```

---

## 12. Tìm điểm gây fault

Manh mối còn lại là:

```text
relay_buf: 72
comment_braid_max: 32
comment_literal: tối đa 64 bytes
```

Trong `capsule.py`, các comment record giống như một ngôn ngữ nhỏ để sửa replay/relay buffer.

Mình thấy:

- `comment_literal` cho ghi tối đa 64 bytes.
- `comment_braid_fill` ghi từ 17 đến 32 bytes.
- `relay_buf` chỉ dài 72 bytes.

Ý tưởng:

```text
Ghi gần đầy relay buffer, sau đó dùng braid_fill ghi tiếp để vượt qua biên 72 bytes.
```

Ví dụ:

```text
64 bytes literal
8 bytes literal
17 bytes braid_fill
```

Tổng cộng:

```text
64 + 8 + 17 = 89 bytes
```

Trong khi `relay_buf` chỉ có 72 bytes.

Vậy phần ghi dư có thể đè vào state phía sau relay buffer, làm ảnh hưởng đến quá trình RSA-CRT signing.

---

## 13. Gây faulty signature

Script thứ hai làm các bước:

1. Xin một chữ ký bình thường cho safe capsule.
2. Gửi comment gây fault.
3. Xin một chữ ký nữa.
4. Kiểm tra chữ ký thứ hai có phải faulty signature không.
5. Tính `gcd`.
6. Recover `p`, `q`, `d`.
7. Lưu private key vào JSON.

Chạy:

```bash
python3 scripts/02_factor_rsa_from_fault.py 178.105.199.41 20000
```

Output thành công:

```text
[+] factored n
p = 9da033fd0799399257825aff0f7ca4b7866a4db13e250be52e50d7fc3d3eb295
q = b6f7221baafa0048953633e0193e92928aab4bf4dba728b6f713e55135c0b6b5
[+] private exponent
d = ...
[+] saved key to paper_lantern_key.json
```

Nếu có ảnh recover key, chèn ở đây:

![Recover key](./assets/4.png)

---

## 14. Forge chữ ký cho unsafe opcode

Sau khi đã có private key `d`, mình không cần xin server ký unsafe opcode nữa.

Mình tự ký canonical message tương ứng với unsafe capsule:

```python
unsafe_canon = b"FH"
unsafe_m = fdh_from_canonical(unsafe_canon, n)
forged_sig = pow(unsafe_m, d, n)
```

Sau đó kiểm tra local:

```python
assert pow(forged_sig, e, n) == unsafe_m
```

Nếu check đúng, chữ ký này hợp lệ theo RSA.

---

## 15. Chạy forbidden opcode

Script cuối tạo chương trình:

```python
program = capsule.rec_raw(0x7f) + capsule.rec_halt()
```

Rồi gửi:

```text
FT_RUN + forged_signature
```

Chạy:

```bash
python3 scripts/03_solve_forge_unsafe_opcode.py 178.105.199.41 20000
```

Output:

```text
[+] signed forbidden capsule
canonical = b'FH'
[*] running forbidden opcode against 178.105.199.41:20000...
slopped{faulted_crt_seams_burn_open}
```

Nếu có ảnh final flag, chèn ở đây:

![Final flag](./assets/final-flag.png)

---

## 16. Scripts

Mình tách exploit thành 3 script để dễ debug từng giai đoạn.

| Script | Mục đích |
|---|---|
| [`01_test_safe_signature.py`](./scripts/test.py) | Test protocol, handshake, tạo safe capsule và xin chữ ký hợp lệ |
| [`02_factor_rsa_from_fault.py`](./scripts/factor.py) | Gây CRT fault, tính GCD, recover `p`, `q`, `d` |
| [`03_solve_forge_unsafe_opcode.py`](./scripts/solve.py) | Dùng private key để ký opcode `0x7f` và lấy flag |

---

## 18. Flag

```text
slopped{faulted_crt_seams_burn_open}
```

---

##

Mấu chốt bài này không phải là buffer overflow thông thường.

Mấu chốt là:

```text
comment và replay buffer overflow
-> gây lỗi RSA-CRT signing
-> lấy faulty signature
-> dùng GCD tính n
-> tính private key d
-> forge signature cho unsafe opcode
-> chạy opcode 0x7f lấy flag
```

---

