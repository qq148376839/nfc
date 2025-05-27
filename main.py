import random
import datetime
from typing import Union
import os

def generate_sector2_block3(date: str = None, suffix: str = None) -> str:
    """
    生成扇区2块3的数据
    :param date: 日期字符串，如果为None则使用当天日期
    :param suffix: 尾号，如果为None则随机生成
    :return: 32字符的十六进制字符串
    """
    if date is None:
        date = datetime.datetime.now().strftime('%Y%m%d')
    if suffix is None:
        suffix = generate_random_suffix()
    
    str_data = f"{date}BB{suffix}"
    return ''.join([hex(ord(c))[2:].zfill(2).upper() for c in str_data])

def generate_random_suffix() -> str:
    """
    生成6位随机数字
    :return: 6位数字字符串
    """
    return str(random.randint(100000, 999999))

def generate_random_hex(bytes_length: int) -> str:
    """
    生成指定长度的随机十六进制字符串
    :param bytes_length: 字节数
    :return: 十六进制字符串
    """
    return ''.join([hex(random.randint(0, 255))[2:].zfill(2).upper() 
                   for _ in range(bytes_length)])

def generate_random_block_data() -> str:
    """
    生成随机的16字节十六进制字符串
    :return: 32字符的十六进制字符串
    """
    return generate_random_hex(16)

def write_hex_to_pos(buffer: bytearray, hex_str: str, position: int) -> None:
    """
    将十六进制字符串写入指定位置
    :param buffer: 目标缓冲区
    :param hex_str: 十六进制字符串
    :param position: 写入位置
    """
    if len(hex_str) != 32:
        raise ValueError('Hex string must be 32 chars (16 bytes)')
    for i in range(16):
        byte = int(hex_str[i*2:i*2+2], 16)
        buffer[position + i] = byte

def generate_binary_mfd(sector0_block1: str = None, 
                       sector0_block2: str = None, 
                       sector2_block3: str = None) -> bytes:
    """
    生成MIFARE Classic 1K格式的二进制MFD数据
    :param sector0_block1: 扇区0块1的16字节十六进制字符串
    :param sector0_block2: 扇区0块2的16字节十六进制字符串
    :param sector2_block3: 扇区2块3的16字节十六进制字符串
    :return: 1024字节的MFD二进制数据
    """
    # 创建1024字节的缓冲区
    buffer = bytearray(1024)
    
    # 如果参数为None，生成随机数据
    if sector0_block1 is None:
        sector0_block1 = generate_random_block_data()
    if sector0_block2 is None:
        sector0_block2 = generate_random_block_data()
    if sector2_block3 is None:
        sector2_block3 = generate_sector2_block3()
    
    # 扇区0
    write_hex_to_pos(buffer, '11EEE82A3D080400047AC493FC85B798', 0)  # 块0
    write_hex_to_pos(buffer, sector0_block1, 16)  # 块1
    write_hex_to_pos(buffer, sector0_block2, 32)  # 块2
    write_hex_to_pos(buffer, '702A2630344B07878F692857385F6829', 48)  # 块3
    
    # 扇区1
    write_hex_to_pos(buffer, '1644FCA83EDE58D64683C53899F40AE4', 64)  # 块0
    write_hex_to_pos(buffer, 'D10560C1F76AC151BF0732E6760052A4', 80)  # 块1
    write_hex_to_pos(buffer, 'D10560C1F76AC151BF0732E6760052A4', 96)  # 块2
    write_hex_to_pos(buffer, '702A2630344B61E789692857385F6829', 112)  # 块3
    
    # 扇区2
    write_hex_to_pos(buffer, 'D10560C1F76AC151BF0732E6760052A4', 128)  # 块0
    write_hex_to_pos(buffer, 'D10560C1F76AC151BF0732E6760052A4', 144)  # 块1
    write_hex_to_pos(buffer, sector2_block3, 160)  # 块2
    write_hex_to_pos(buffer, '702A2630344B34B78C692857385F6829', 176)  # 块3
    
    # 扇区3-15 (填充空白数据和默认密钥)
    for sector in range(3, 16):
        sector_start = sector * 64
        # 块0-2填充0
        for block in range(3):
            write_hex_to_pos(buffer, '00000000000000000000000000000000', 
                           sector_start + block*16)
        # 块3 (扇区尾部)
        write_hex_to_pos(buffer, 'FFFFFFFFFFFFFF078069FFFFFFFFFFFF', 
                        sector_start + 48)
    
    return bytes(buffer)

def save_mfd_file(data: bytes, filename: str = 'output.mfd') -> None:
    """
    保存MFD文件
    :param data: 二进制数据
    :param filename: 文件名
    """
    with open(filename, 'wb') as f:
        f.write(data)

if __name__ == '__main__':
    # 示例使用
    mfd_data = generate_binary_mfd()
    save_mfd_file(mfd_data)
    print(f"MFD文件已生成: output.mfd")
