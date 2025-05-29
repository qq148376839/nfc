import random
import datetime
from typing import Union, List, Dict, Optional
import os
import subprocess
import platform
import argparse
import time
import logging
import shutil
import threading
import queue
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
        
        # NFC监听相关
        self.nfc_process: Optional[subprocess.Popen] = None
        self.nfc_queue = queue.Queue()
        self.nfc_thread: Optional[threading.Thread] = None
        self.is_running = False
        self.current_uid = ""
        self.last_update_time = 0
        self.update_interval = 0.1  # 100ms更新间隔

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

    def start_nfc_monitor(self):
        """
        启动NFC监听进程
        """
        if self.nfc_process is not None:
            return

        try:
            # 启动nfc-list进程，持续运行
            self.nfc_process = subprocess.Popen(
                [self.nfc_list_cmd, '-t', '1'],  # -t 1 表示每秒更新一次
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # 行缓冲
                universal_newlines=True
            )
            
            self.is_running = True
            self.nfc_thread = threading.Thread(target=self._monitor_nfc_output)
            self.nfc_thread.daemon = True
            self.nfc_thread.start()
            logger.info("NFC监听进程已启动")
            
        except Exception as e:
            logger.error(f"启动NFC监听进程失败: {str(e)}")
            self.stop_nfc_monitor()
            raise

    def stop_nfc_monitor(self):
        """
        停止NFC监听进程
        """
        self.is_running = False
        if self.nfc_process is not None:
            try:
                self.nfc_process.terminate()
                self.nfc_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.nfc_process.kill()
            except Exception as e:
                logger.warning(f"停止NFC监听进程时发生错误: {str(e)}")
            finally:
                self.nfc_process = None
        
        if self.nfc_thread is not None:
            self.nfc_thread.join(timeout=2)
            self.nfc_thread = None

    def _monitor_nfc_output(self):
        """
        监控NFC输出
        """
        while self.is_running and self.nfc_process is not None:
            try:
                # 非阻塞方式读取输出
                output = self.nfc_process.stdout.readline()
                if output:
                    # 解析输出获取UID
                    if "UID (NFCID1)" in output:
                        uid = output.split(':')[-1].strip()
                        self.current_uid = uid
                        self.last_update_time = time.time()
                    elif "No NFC device found" in output:
                        self.current_uid = ""
                        self.last_update_time = time.time()
                elif self.nfc_process.poll() is not None:
                    # 进程已结束
                    break
                    
            except Exception as e:
                logger.error(f"读取NFC输出时发生错误: {str(e)}")
                break
        
        self.is_running = False
        logger.info("NFC监听进程已停止")

    def get_current_uid(self) -> str:
        """
        获取当前标签UID
        :return: str 当前标签UID
        """
        # 检查是否需要更新
        current_time = time.time()
        if current_time - self.last_update_time > self.update_interval:
            # 如果超过更新间隔，重新获取一次
            try:
                result = subprocess.run(
                    [self.nfc_list_cmd],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    timeout=1
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if "UID (NFCID1)" in line:
                            self.current_uid = line.split(':')[-1].strip()
                            self.last_update_time = current_time
                            break
            except Exception:
                pass
        return self.current_uid

    def wait_for_new_tag(self, processed_uids: List[str], timeout: float = 30.0) -> str:
        """
        等待新的标签放入
        :param processed_uids: 已处理的标签UID列表
        :param timeout: 超时时间（秒）
        :return: str 新标签的UID
        """
        logger.info("请放入新的标签...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            current_uid = self.get_current_uid()
            if current_uid:
                if current_uid not in processed_uids:
                    logger.info(f"检测到新标签，UID: {current_uid}")
                    return current_uid
                else:
                    logger.warning("检测到已处理的标签，请移除后放入新标签")
            time.sleep(0.1)  # 100ms的轮询间隔
            
        logger.error("等待新标签超时")
        return ""

    def check_nfc_reader(self) -> bool:
        """
        检查NFC读写器是否正确安装和连接
        :return: bool 是否检测到NFC读写器
        """
        try:
            # 启动NFC监听进程
            self.start_nfc_monitor()
            
            # 等待一小段时间确保进程启动
            time.sleep(0.5)
            
            # 检查进程是否正常运行
            if self.nfc_process is None or self.nfc_process.poll() is not None:
                logger.error("NFC监听进程未正常运行")
                return False
                
            # 尝试获取一次设备状态
            result = subprocess.run(
                [self.nfc_list_cmd],
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=2
            )
            
            if result.returncode != 0:
                logger.error("NFC读写器未正确安装或未连接")
                return False
                
            if "No NFC device found" in result.stdout:
                logger.error("未检测到NFC设备")
                return False
                
            logger.info("NFC读写器检测成功")
            return True
            
        except Exception as e:
            logger.error(f"检测NFC读写器时发生错误: {str(e)}")
            self.stop_nfc_monitor()
            return False

    def __del__(self):
        """
        析构函数，确保清理资源
        """
        self.stop_nfc_monitor()

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
    parser.add_argument('--timeout', type=float, default=30.0, help='等待标签超时时间(秒) (默认: 30)')
    
    args = parser.parse_args()
    
    nfc = NFCController()
    try:
        # 检查NFC读写器
        if not nfc.check_nfc_reader():
            logger.error("程序终止：NFC读写器未就绪")
            return
        
        # 开始处理标签
        for i in range(args.count):
            logger.info(f"开始处理第 {i+1}/{args.count} 个标签")
            
            # 等待新标签
            current_uid = nfc.wait_for_new_tag(nfc.processed_uids, args.timeout)
            if not current_uid:
                logger.error("未能获取到有效的标签UID")
                continue
                
            # 生成临时文件名
            temp_read_file = nfc.temp_dir / generate_filename("temp_read", i+1)
            temp_write_file = nfc.temp_dir / generate_filename("temp_write", i+1)
            final_file = Path(generate_filename(args.prefix, i+1))
            
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
        # 清理资源
        nfc.stop_nfc_monitor()
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
