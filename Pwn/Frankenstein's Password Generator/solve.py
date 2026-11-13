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
