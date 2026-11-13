# Write-Up: Frankenstein's Password Generator (Reverse Engineering)

## 📌 Tổng quan thử thách (Challenge Overview)
- **Tên bài:** Frankenstein's Password Generator v1.0
- **Thể loại:** Reverse Engineering
- **Mô tả:** 
  > *Dr. Frankenstein left behind a strange password generator in an abandoned NJIT laboratory. The machine refuses to start without an activation phrase. His last notebook entry reads, "A bolt at midnight gave it life."*

## 🛠️ Bước 1: Phân tích mã giả (Static Analysis with Ghidra)

### 1. Hàm chính (`main` / `FUN_004012a5`)
Chương trình sử dụng `fgets` để nhận chuỗi đầu vào từ người dùng (tối đa 127 ký tự), loại bỏ ký tự xuống dòng (`\n`), sau đó truyền vào hàm kiểm tra `FUN_00401176`.

```c
undefined8 FUN_004012a5(void) {
  int iVar1;
  char *pcVar2;
  undefined8 uVar3;
  size_t sVar4;
  char local_88 [128];
  
  puts("FRANKENSTEIN\'S PASSWORD GENERATOR v1.0");
  // ... (In các thông điệp gợi ý)
  pcVar2 = fgets(local_88, 0x80, stdin);
  if (pcVar2 == (char *)0x0) {
    uVar3 = 1;
  } else {
    sVar4 = strcspn(local_88, "\r\n");
    local_88[sVar4] = '\0';
    iVar1 = FUN_00401176(local_88); // Hàm kiểm tra activation phrase
    if (iVar1 == 0) {
      puts("The machine crackles, then falls silent. Incorrect phrase.");
      uVar3 = 1;
    } else {
      puts("The laboratory lights flicker. IT\'S ALIVE!");
      FUN_004011f9(local_88); // Hàm giải mã thông điệp tiếp theo
      uVar3 = 0;
    }
  }
  return uVar3;
}
```

<img width="813" height="776" alt="image" src="https://github.com/user-attachments/assets/5eb78d61-f2f0-4312-a502-6b53d9c19aa6" />

### 2. Hàm kiểm tra mật khẩu (`FUN_00401176`)
Hàm này thực hiện hai việc chính:
1. Kiểm tra độ dài chuỗi bắt buộc phải bằng $14$ ký tự ($0xe$).
2. Duyệt qua từng ký tự và áp dụng công thức toán học để đối chiếu với mảng mục tiêu `"*$*)C7EP\\]erto"`:

$$
check\_formula = (i \times 7 + (param\_1[i] \oplus 0x5d) + 11) \pmod{256} == target[i]
$$

```c
undefined8 FUN_00401176(char *param_1) {
  size_t sVar1;
  undefined8 uVar2;
  ulong local_10;
  
  sVar1 = strlen(param_1);
  if (sVar1 == 0xe) {
    for (local_10 = 0; local_10 < 0xe; local_10 = local_10 + 1) {
      if ((byte)((char)local_10 * '\a' + (param_1[local_10] ^ 0x5dU) + '\v') !=
          "*$*)C7EP\\]erto"[local_10]) {
        return 0;
      }
    }
    uVar2 = 1;
  } else {
    uVar2 = 0;
  }
  return uVar2;
}
```

<img width="827" height="607" alt="image" src="https://github.com/user-attachments/assets/8b473d34-097e-4d57-8d68-e89711c9aec7" />

---

## 💡 Bước 2: Giải mã và Khai thác (Exploitation & Solving)

Từ công thức kiểm tra trong mã nguồn, ta suy ngược lại công thức tính ký tự gốc:

$$
\mathrm{param}_1[i] = ((\mathrm{target}[i] - 7 \times i - 11) \text{ AND } \text{0xFF}) \oplus \text{0x5d}
$$

Kết hợp với gợi ý từ cốt truyện của bài (*"A bolt at midnight gave it life"*), ta thu được activation phrase chính xác là: **`BOLTATMINDNIGHT`**.

### Script Python tự động giải quyết thử thách (`solve.py`):
```python
from pwn import *

context.binary = './frankenstein'
context.log_level = 'info'

def exploit():
    # Khởi động tiến trình
    io = process('./frankenstein')
    
    # Payload chính xác
    payload = b'BOLTATMIDNIGHT'
    
    # Gửi payload sau khi nhận được yêu cầu
    io.sendlineafter(b'Activation phrase: ', payload)
    
    # Nhận toàn bộ phản hồi từ chương trình (bao gồm thông điệp giải mã)
    response = io.recvall(timeout=2)
    
    print("\n[+] Kết quả từ chương trình:")
    print(response.decode(errors='ignore'))

if __name__ == '__main__':
    exploit()
```
---

## 🏆 Kết quả
Sau khi gửi đúng activation phrase `BOLTATMIDNIGHT`, chương trình kích hoạt hàm giải mã `FUN_004011f9` và thành công đánh thức "sinh vật", in ra thông điệp bí mật / flag hoàn chỉnh.
```text
The laboratory lights flicker. IT'S ALIVE!
The creature whispers: <Flag / Secret Message>
```
<img width="763" height="152" alt="image" src="https://github.com/user-attachments/assets/47f4e91e-7f2d-4d47-9df8-d36351f2329a" />
