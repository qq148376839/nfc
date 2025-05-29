import random
import datetime
from typing import Union, List, Dict
import os
import subprocess
import platform
import argparse
import time
import logging
import shutil
from pathlib import Path

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nfc_write.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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

class NFCController:
    def __init__(self):
        self.system = platform.system().lower()
        self.nfc_list_cmd = 'nfc-list'
        self.nfc_mfclassic_cmd = 'nfc-mfclassic'
        self.processed_uids: List[str] = []  # 用于存储已处理的标签UID
        self.temp_dir = Path('temp_mfd_files')
        self.generated_files: List[Path] = []  # 用于跟踪生成的文件
        self.cleanup_old_files()
        self.temp_dir.mkdir(exist_ok=True)

    def cleanup_old_files(self):
        """
        清理旧文件
        """
        # 清理临时目录
        if self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir)
                logger.info("已清理旧的临时文件目录")
            except Exception as e:
                logger.warning(f"清理临时目录时发生错误: {str(e)}")

        # 清理当前目录下的.mfd文件
        try:
            for file in Path('.').glob('*.mfd'):
                if file.name.startswith('tag_') or file.name.startswith('temp_'):
                    try:
                        file.unlink()
                        logger.info(f"已删除旧文件: {file.name}")
                    except Exception as e:
                        logger.warning(f"删除文件 {file.name} 时发生错误: {str(e)}")
        except Exception as e:
            logger.warning(f"清理旧文件时发生错误: {str(e)}")

    def cleanup_generated_files(self, keep_files: bool = False):
        """
        清理生成的文件
        :param keep_files: 是否保留文件
        """
        if not keep_files:
            for file in self.generated_files:
                try:
                    if file.exists():
                        file.unlink()
                        logger.info(f"已删除生成的文件: {file.name}")
                except Exception as e:
                    logger.warning(f"删除文件 {file.name} 时发生错误: {str(e)}")

    def check_nfc_reader(self) -> bool:
        """
        检查NFC读写器是否正确安装和连接
        :return: bool 是否检测到NFC读写器
        """
        try:
            result = subprocess.run(
                [self.nfc_list_cmd],
                capture_output=True,
                text=True,
                encoding='utf-8'
            )
            
            if result.returncode != 0:
                logger.error("NFC读写器未正确安装或未连接")
                return False
                
            # 检查输出中是否包含NFC设备信息
            if "No NFC device found" in result.stdout:
                logger.error("未检测到NFC设备")
                return False
                
            logger.info("NFC读写器检测成功")
            return True
            
        except FileNotFoundError:
            logger.error("未找到nfc-list命令，请确保已安装libnfc工具包")
            return False
        except Exception as e:
            logger.error(f"检测NFC读写器时发生错误: {str(e)}")
            return False

    def get_tag_uid(self) -> str:
        """
        获取当前标签的UID
        :return: str 标签UID，如果没有标签则返回空字符串
        """
        try:
            result = subprocess.run(
                [self.nfc_list_cmd],
                capture_output=True,
                text=True,
                encoding='utf-8'
            )
            
            if result.returncode != 0:
                return ""
                
            # 解析输出获取UID
            for line in result.stdout.split('\n'):
                if "UID (NFCID1)" in line:
                    uid = line.split(':')[-1].strip()
                    return uid
            return ""
            
        except Exception as e:
            logger.error(f"获取标签UID时发生错误: {str(e)}")
            return ""

    def wait_for_new_tag(self, processed_uids: List[str], poll_interval: float = 0.1) -> str:
        """
        等待新的标签放入，使用轮询方式检测
        :param processed_uids: 已处理的标签UID列表
        :param poll_interval: 轮询间隔（秒），默认0.1秒
        :return: str 新标签的UID
        """
        logger.info("请放入新的标签...")
        last_uid = ""
        no_tag_count = 0
        
        while True:
            current_uid = self.get_tag_uid()
            
            # 如果没有检测到标签
            if not current_uid:
                if last_uid:  # 如果之前有标签，说明标签被移除了
                    logger.info("标签已移除，等待新标签...")
                    last_uid = ""
                no_tag_count += 1
                if no_tag_count % 10 == 0:  # 每10次轮询提示一次
                    logger.info("等待放入新标签...")
                time.sleep(poll_interval)
                continue
            
            # 如果检测到标签
            if current_uid != last_uid:  # 标签发生变化
                if current_uid in processed_uids:
                    logger.warning("检测到已处理的标签，请移除后放入新标签")
                    last_uid = current_uid
                else:
                    logger.info(f"检测到新标签，UID: {current_uid}")
                    return current_uid
            
            last_uid = current_uid
            time.sleep(poll_interval)

    def read_tag_to_file(self, filename: str) -> bool:
        """
        读取标签内容到文件
        :param filename: 输出文件名
        :return: bool 是否成功
        """
        try:
            result = subprocess.run(
                [self.nfc_mfclassic_cmd, 'R', 'a', 'u', filename],
                capture_output=True,
                text=True,
                encoding='utf-8'
            )
            
            if result.returncode != 0:
                logger.error(f"读取标签失败: {result.stderr}")
                return False
                
            logger.info(f"标签读取成功，已保存到: {filename}")
            return True
            
        except Exception as e:
            logger.error(f"读取标签时发生错误: {str(e)}")
            return False

    def write_tag_from_file(self, source_file: str, target_file: str, max_retries: int = 3) -> bool:
        """
        将文件内容写入标签
        :param source_file: 源文件
        :param target_file: 目标文件
        :param max_retries: 最大重试次数
        :return: bool 是否成功
        """
        for attempt in range(max_retries):
            try:
                result = subprocess.run(
                    [self.nfc_mfclassic_cmd, 'w', 'ab', 'u', source_file, target_file],
                    capture_output=True,
                    text=True,
                    encoding='utf-8'
                )
                
                if "Done" in result.stdout and "blocks written" in result.stdout:
                    logger.info(f"标签写入成功 (尝试 {attempt + 1}/{max_retries})")
                    return True
                    
                logger.warning(f"标签写入可能未完全成功 (尝试 {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    logger.info("等待5秒后重试...")
                    time.sleep(5)
                    
            except Exception as e:
                logger.error(f"写入标签时发生错误 (尝试 {attempt + 1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(5)
                    
        return False

def generate_filename(prefix: str = "tag", index: int = 1) -> str:
    """
    生成文件名
    :param prefix: 文件名前缀
    :param index: 序号
    :return: str 生成的文件名
    """
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"{prefix}_{timestamp}_{index:03d}.mfd"

def main():
    parser = argparse.ArgumentParser(description='NFC标签写入工具')
    parser.add_argument('--date', type=str, help='日期 (格式: YYYYMMDD)，为空则使用当天日期')
    parser.add_argument('--suffix', type=str, help='尾号，为空则随机生成')
    parser.add_argument('--count', type=int, default=1, help='写入标签数量 (默认: 1)')
    parser.add_argument('--prefix', type=str, default='tag', help='输出文件前缀 (默认: tag)')
    parser.add_argument('--keep-files', action='store_true', help='保留生成的文件 (默认: 不保留)')
    
    args = parser.parse_args()
    
    # 检查NFC读写器
    nfc = NFCController()
    if not nfc.check_nfc_reader():
        logger.error("程序终止：NFC读写器未就绪")
        return
    
    try:
        # 开始处理标签
        for i in range(args.count):
            logger.info(f"开始处理第 {i+1}/{args.count} 个标签")
            
            # 等待新标签
            current_uid = nfc.wait_for_new_tag(nfc.processed_uids)
            if not current_uid:
                logger.error("未能获取到有效的标签UID")
                continue
                
            # 生成临时文件名
            temp_read_file = nfc.temp_dir / generate_filename("temp_read", i+1)
            temp_write_file = nfc.temp_dir / generate_filename("temp_write", i+1)
            final_file = Path(generate_filename(args.prefix, i+1))
            
            # 读取标签
            if not nfc.read_tag_to_file(str(temp_read_file)):
                logger.error("读取标签失败，跳过当前标签")
                continue
                
            # 生成新的MFD数据
            try:
                mfd_data = generate_binary_mfd(
                    sector2_block3=generate_sector2_block3(args.date, args.suffix)
                )
                with open(temp_write_file, 'wb') as f:
                    f.write(mfd_data)
            except Exception as e:
                logger.error(f"生成MFD数据失败: {str(e)}")
                continue
                
            # 写入标签
            if nfc.write_tag_from_file(str(temp_write_file), str(temp_read_file)):
                # 写入成功，保存最终文件
                os.rename(temp_write_file, final_file)
                nfc.generated_files.append(final_file)  # 添加到生成文件列表
                nfc.processed_uids.append(current_uid)
                logger.info(f"标签 {i+1} 处理完成，最终文件: {final_file}")
            else:
                logger.error(f"标签 {i+1} 写入失败")
                
            # 清理临时文件
            try:
                temp_read_file.unlink(missing_ok=True)
                temp_write_file.unlink(missing_ok=True)
            except Exception as e:
                logger.warning(f"清理临时文件时发生错误: {str(e)}")
                
            if i < args.count - 1:
                logger.info("请移除当前标签，准备处理下一个标签...")
                time.sleep(2)
        
        logger.info("所有标签处理完成")
        
    finally:
        # 清理生成的文件
        nfc.cleanup_generated_files(keep_files=args.keep_files)
        # 清理临时目录
        try:
            if nfc.temp_dir.exists():
                shutil.rmtree(nfc.temp_dir)
                logger.info("已清理临时文件目录")
        except Exception as e:
            logger.warning(f"清理临时目录时发生错误: {str(e)}")

if __name__ == '__main__':
    main()
