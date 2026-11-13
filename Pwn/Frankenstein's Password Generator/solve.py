from pwn import *

context.binary = './frankenstein'
context.log_level = 'debug'  # Bật chế độ debug để thấy rõ data gửi/nhận

def exploit():
    io = process('./frankenstein')
    
    # Chuỗi chính xác tuyệt đối, không khoảng trắng, viết hoa 100%
    payload = b'BOLTATMIDNIGHT'
    
    # Gửi payload sau khi nhận được prompt
    io.sendlineafter(b'Activation phrase: ', payload)
    
    # Nhận toàn bộ kết quả phản hồi
    response = io.recvall(timeout=2)
    
    print("\n[+] Kết quả từ chương trình:")
    print(response.decode(errors='ignore'))

if __name__ == '__main__':
    exploit()
