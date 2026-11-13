# Writeup: Philophobia - SpookyCTF

- **Challenge Name:** Too Much Love is Scary (philophobia)
- **Category:** Pwn / Reverse Engineering
- **Points:** 500
- **Format flag:** `spooky{...}`

---

## 1. Tổng quan đề bài

Đề bài cung cấp một tệp binary ELF 64-bit mang tên `philophobia`. Mô tả thử thách xoay quanh chủ đề tình yêu và chứng sợ yêu ("Too Much Love is Scary"), yêu cầu chúng ta phân tích logic, vượt qua các điều kiện kiểm tra đầu vào để kích hoạt hàm in flag.

---

## 2. Phân tích ban đầu (Reconnaissance)

Trước tiên, ta kiểm tra thông tin tệp binary và quyền thực thi:

```bash
chmod +x philophobia
./philophobia
```

<img width="1461" height="536" alt="image" src="https://github.com/user-attachments/assets/b657ef6f-7512-437c-b4cc-d7b431d5d652" />

Khi chạy chương trình, nó sẽ in ra một đoạn thơ và yêu cầu nhập hai số nguyên (`start` và `end`), sau đó yêu cầu nhập một chuỗi dựa trên khoảng chênh lệch.

---

## 3. Dịch ngược mã nguồn (`main` function)

Sử dụng công cụ Ghidra hoặc IDA Pro để phân tích hàm `main`:

```c
undefined8 main(void)
{
  int iVar1;
  long in_FS_OFFSET;
  int local_420;
  undefined4 local_41c;
  char local_418 [32];
  char local_3f8 [1000];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  local_420 = 0;
  local_41c = 0;
  // ... in các đoạn thơ ...
  printf("The walls of Troy leave our lovers apart. They start small, must change and become complete. Enter where the heart breaks (Enter <start end>): ");
  iVar1 = __isoc23_scanf("%d %d",&local_420,&local_41c);
  if (iVar1 != 2) {
    puts("\nInvalid input format.");
    exit(1);
  }
  getchar();
  printf("Now based on our difference speak about a certain famous summer day. Make sure that it is aimed at the right spot in the heart: ");
  fgets(local_3f8,1000,stdin);
  builtin_strncpy(local_418,"Shall I compare thee",0x14);
  iVar1 = strncmp(local_3f8 + local_420,local_418,0x14);
  if (iVar1 == 0) {
    print_flag(local_420,local_41c);
  }
  else {
    puts("\n..no..No...NO...NOOOOOO");
  }
  // ...
}
```

### Phân tích logic `main`:
1. **Nhập `start` và `end`:** Lưu vào `local_420` (`start`) và `local_41c` (`end`).
2. **Nhập chuỗi:** Đọc tối đa 1000 ký tự vào buffer `local_3f8` bằng `fgets`.
3. **So sánh (`strncmp`):** 
   - Chương trình copy chuỗi `"Shall I compare thee"` (độ dài `0x14` = 20 bytes) vào `local_418`.
   - So sánh 20 bytes tại vị trí `local_3f8 + start` với `local_418`.
   - Nếu khớp hoàn toàn (`iVar1 == 0`), gọi hàm `print_flag(start, end)`.

---

## 4. Khám phá cách vượt qua `strncmp` (Stack Offset)

Nhìn vào khai báo biến cục bộ trên stack:
- `local_3f8` (Buffer chứa chuỗi nhập vào) nằm ở offset `-0x3f8`.
- `local_418` (Biến lưu chuỗi mẫu) nằm ở offset `-0x418`.

Khoảng cách giữa hai ô nhớ này là:
$$\text{Offset} = 0x418 - 0x3f8 = 0x20 \text{ (32 hệ thập phân)}$$

Do đó, nếu ta chọn **`start = 32`**, con trỏ `local_3f8 + 32` sẽ trỏ thẳng đến ô nhớ của biến `local_418` (nơi đã có sẵn chuỗi `"Shall I compare thee"`). Điều kiện `strncmp` sẽ luôn trả về `0` thành công bất kể ta nhập gì ở chuỗi phía sau.

---

## 5. Phân tích hàm giải mã `print_flag`

Tiếp theo, xem xét mã nguồn của hàm `print_flag`:

<img width="831" height="272" alt="image" src="https://github.com/user-attachments/assets/236556b1-8658-4423-af04-b388be7ae675" />

```c
void print_flag(int param_1,int param_2)
{
  long in_FS_OFFSET;
  int local_40;
  byte local_38 [40];
  long local_10;
  
  // ... khởi tạo mảng local_38 chứa byte mã hóa ...
  puts("\n I guess I don't have a choice...");
  for (local_40 = 0; local_38[local_40] != 0; local_40 = local_40 + 1) {
    putchar((uint)local_38[local_40] ^ (param_2 - param_1) + 0x47U);
  }
  putchar(10);
  // ...
}
```

### Thuật toán giải mã:

Mỗi byte trong mảng local_38 được giải mã bằng phép toán XOR:

Plaintext = Ciphertext ^ ((end - start) + 0x47)

Vì định dạng flag bắt đầu bằng spooky{, byte đầu tiên của mảng mã hóa là 0x29. Ta tính được Key:

0x29 ^ Key = 0x73 ('s') => Key = 90

Thay vào công thức:

90 = (end - start) + 71 => end - start = 19

Với start = 32, suy ra end = 32 + 19 = 51.

---

## 6. Khải thác và Lấy Flag

1. Ở bước nhập `<start end>`, nhập:
   ```text
   32 51
   ```
2. Ở bước nhập chuỗi tiếp theo, để đảm bảo an toàn và khớp với độ trượt 32 byte, nhập:
   ```text
   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAShall I compare thee
   ```

<img width="1467" height="646" alt="image" src="https://github.com/user-attachments/assets/8c622895-e14d-4b61-9f72-1ca7f4f235ec" />
