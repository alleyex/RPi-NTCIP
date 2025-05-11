import socket
import struct
import logging
import time
import yaml
import os
from typing import Optional, Tuple, List
from .ntcip_parser import NTCIPParser

# 定義顏色代碼
class Colors:
    GREEN = '\033[32m'
    PURPLE = '\033[35m'
    RESET = '\033[0m'

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        # 根據不同的日誌訊息類型使用不同的顏色
        if record.name == 'NTCIPServer':
            if record.getMessage().startswith('已發送ACK:') or record.getMessage().startswith('收到控制中心 ACK:'):
                record.msg = f"{Colors.GREEN}{record.msg}{Colors.RESET}"
            elif record.getMessage().startswith('收到原始資料:'):
                record.msg = f"{Colors.PURPLE}{record.msg}{Colors.RESET}"
        return super().format(record)

class NTCIPServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 5000):
        self.parser = NTCIPParser()
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.logger = logging.getLogger('NTCIPServer')
        self.control_center_ip = self._load_control_center_ip()
        self.is_test_mode = os.environ.get('NTCIP_TEST_MODE') == '1'
        
        # 設定更詳細的日誌格式
        self.logger.setLevel(logging.DEBUG)
        formatter = ColoredFormatter('%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
        
        # 設定 NTCIPParser 的日誌格式
        parser_logger = logging.getLogger('NTCIPParser')
        parser_logger.setLevel(logging.DEBUG)
        parser_logger.addHandler(logging.StreamHandler())
        parser_logger.handlers[0].setFormatter(formatter)
        
        # 檔案處理器 - 使用兩個不同的日誌檔案
        # 1. 一般日誌
        file_handler = logging.FileHandler('ntcip_server.log')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # 2. 通訊流程日誌
        comm_handler = logging.FileHandler('ntcip_communication.log')
        comm_handler.setLevel(logging.DEBUG)
        comm_handler.setFormatter(formatter)
        self.logger.addHandler(comm_handler)
        
        # 控制台處理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
    def _load_control_center_ip(self) -> str:
        """從設定檔載入控制中心IP位址"""
        try:
            self.logger.debug("開始載入控制中心IP設定")
            # 嘗試多個可能的設定檔路徑
            possible_paths = [
                'config/config.yaml',  # 相對於當前目錄
                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'config.yaml'),  # 相對於程式碼目錄
                os.path.join(os.path.dirname(__file__), '..', 'config', 'config.yaml'),  # 相對於模組目錄
            ]
            
            self.logger.debug(f"搜尋設定檔路徑: {possible_paths}")
            config_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    config_path = path
                    self.logger.debug(f"找到設定檔: {path}")
                    break
                    
            if config_path is None:
                self.logger.error("找不到設定檔")
                return None
                
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                self.logger.debug(f"載入設定檔內容: {config}")
                
                if not config or 'ntcip' not in config:
                    self.logger.error("設定檔格式錯誤：缺少 ntcip 區段")
                    return None
                if 'control_center' not in config['ntcip']:
                    self.logger.error("設定檔格式錯誤：缺少 control_center 區段")
                    return None
                if 'ip' not in config['ntcip']['control_center']:
                    self.logger.error("設定檔格式錯誤：缺少 control_center.ip 設定")
                    return None
                    
                ip = config['ntcip']['control_center']['ip']
                self.logger.info(f"成功載入控制中心IP: {ip}")
                return ip
                
        except Exception as e:
            self.logger.error(f"載入控制中心IP設定失敗: {str(e)}", exc_info=True)
            return None
            
    def _is_control_center(self, client_ip: str) -> bool:
        """檢查是否為控制中心連線"""
        self.logger.debug(f"檢查控制中心IP: {client_ip}")
        # 在測試模式下，允許所有連線
        if self.is_test_mode:
            self.logger.debug("測試模式：允許所有連線")
            return True
        # 如果沒有設定控制中心IP，允許所有連線
        if self.control_center_ip is None:
            self.logger.warning("未設定控制中心IP，允許所有連線")
            return True
            
        is_control = client_ip == self.control_center_ip
        self.logger.debug(f"控制中心IP檢查結果: {is_control}")
        return is_control
        
    def start(self):
        """啟動TCP伺服器"""
        try:
            self.logger.info(f"正在啟動伺服器 {self.host}:{self.port}")
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            self.logger.info(f"伺服器啟動成功，等待連線...")
            
            while self.running:
                try:
                    self.logger.debug("等待新的客戶端連線...")
                    client_socket, client_address = self.server_socket.accept()
                    self.logger.info(f"接受來自 {client_address[0]}:{client_address[1]} 的連線")
                    self.handle_client(client_socket, client_address)
                except Exception as e:
                    if self.running:  # 只有在伺服器仍在運行時才記錄錯誤
                        self.logger.error(f"處理客戶端連線時發生錯誤: {e}", exc_info=True)
        except Exception as e:
            self.logger.error(f"啟動伺服器時發生錯誤: {e}", exc_info=True)
            raise
        finally:
            self.stop()
            
    def stop(self):
        """停止TCP伺服器"""
        self.logger.info("正在停止伺服器...")
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
                self.logger.debug("伺服器socket已關閉")
            except Exception as e:
                self.logger.error(f"關閉伺服器時發生錯誤: {e}", exc_info=True)
            finally:
                self.server_socket = None
        self.logger.info("伺服器已停止")
        
    def handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        """處理客戶端連線"""
        client_ip, client_port = client_address
        self.logger.info(f"開始處理來自 {client_ip}:{client_port} 的連線")
        
        # 檢查是否為控制中心連線
        if not self._is_control_center(client_ip):
            self.logger.warning(f"拒絕非控制中心IP連線: {client_ip}")
            client_socket.close()
            return
            
        try:
            while True:
                # 接收資料
                self.logger.debug("等待接收資料...")
                data = client_socket.recv(1024)
                if not data:
                    self.logger.info(f"控制中心 {client_ip}:{client_port} 關閉連線")
                    break
                    
                self.logger.debug(f"收到原始資料: {data.hex()}")
                
                # 解析資料框
                frame = self.parser.parse_frame(data)
                
                if frame:
                    # 將 info 欄位轉換為十六進制格式
                    frame_hex = frame.copy()
                    frame_hex['info'] = frame['info'].hex()
                    self.logger.info(f"成功解析資料框: {frame_hex}")
                    
                    # 檢查位址是否有效
                    if frame['addr'] == 0xFFFF:  # 無效位址
                        self.logger.warning(f"無效的裝置位址: {frame['addr']}")
                        nak_frame = self.create_nak_frame(frame['seq'], frame['addr'], 0x04)  # 位址錯誤
                        client_socket.send(nak_frame)
                        self.logger.debug(f"已發送NAK: {nak_frame.hex()}")
                        continue
                    
                    # 發送ACK
                    ack_frame = self.create_ack_frame(frame['seq'], frame['addr'])
                    client_socket.send(ack_frame)
                    self.logger.debug(f"已發送ACK: {ack_frame.hex()}")
                    
                    # 處理訊息
                    response = self.process_message(frame)
                    if response:
                        # 發送回應
                        client_socket.send(response)
                        self.logger.debug(f"已發送回應: {response.hex()}")
                        
                        # 等待控制中心的 ACK
                        try:
                            ack_data = client_socket.recv(1024)
                            if ack_data:
                                self.logger.debug(f"收到控制中心 ACK: {ack_data.hex()}")
                                
                                # 解析 ACK
                                ack_result = self.parser.parse_frame(ack_data)
                                if ack_result:
                                    self.logger.debug(f"ACK 解析結果: 序號={ack_result['seq']}, 位址={ack_result['addr']}")
                                    
                                    # 檢查序號是否相符
                                    if ack_result['seq'] != frame['seq']:
                                        self.logger.warning(f"ACK 序號不符: 預期 {frame['seq']}, 實際 {ack_result['seq']}")
                                        # 發送 NAK
                                        nak_frame = self.create_nak_frame(frame['seq'], frame['addr'], 0x02)  # 碼框錯誤
                                        client_socket.send(nak_frame)
                                        self.logger.debug(f"已發送NAK: {nak_frame.hex()}")
                                else:
                                    self.logger.warning("ACK 解析失敗")
                                    # 發送 NAK
                                    nak_frame = self.create_nak_frame(frame['seq'], frame['addr'], 0x02)  # 碼框錯誤
                                    client_socket.send(nak_frame)
                                    self.logger.debug(f"已發送NAK: {nak_frame.hex()}")
                            else:
                                self.logger.warning("未收到控制中心 ACK")
                                # 發送 NAK
                                nak_frame = self.create_nak_frame(frame['seq'], frame['addr'], 0x02)  # 碼框錯誤
                                client_socket.send(nak_frame)
                                self.logger.debug(f"已發送NAK: {nak_frame.hex()}")
                        except socket.timeout:
                            self.logger.warning("等待控制中心 ACK 超時")
                            # 發送 NAK
                            nak_frame = self.create_nak_frame(frame['seq'], frame['addr'], 0x02)  # 碼框錯誤
                            client_socket.send(nak_frame)
                            self.logger.debug(f"已發送NAK: {nak_frame.hex()}")
                        except Exception as e:
                            self.logger.error(f"處理控制中心 ACK 時發生錯誤: {e}")
                            # 發送 NAK
                            nak_frame = self.create_nak_frame(frame['seq'], frame['addr'], 0x02)  # 碼框錯誤
                            client_socket.send(nak_frame)
                            self.logger.debug(f"已發送NAK: {nak_frame.hex()}")
                    else:
                        self.logger.warning("訊息處理未產生回應")
                else:
                    self.logger.warning("資料框解析失敗")
                    # 嘗試從原始資料中提取序號和位址
                    try:
                        # 檢查資料框格式
                        if len(data) < 7:  # 最小長度檢查
                            seq = 0
                            addr = 0
                            err_code = 0x02  # 碼框錯誤
                        elif data[0] != self.parser.DLE:
                            seq = 0
                            addr = 0
                            err_code = 0x01  # 起始碼錯誤
                        elif data[1] != self.parser.STX:
                            seq = 0
                            addr = 0
                            err_code = 0x01  # 起始碼錯誤
                        else:
                            # 正確提取序號和位址
                            seq = data[2]
                            addr = (data[3] << 8) | data[4]
                            err_code = 0x02  # 碼框錯誤
                    except IndexError:
                        # 如果無法提取序號和位址，使用預設值
                        seq = 0
                        addr = 0
                        err_code = 0x02  # 碼框錯誤
                    
                    # 發送NAK
                    nak_frame = self.create_nak_frame(seq, addr, err_code)
                    client_socket.send(nak_frame)
                    self.logger.debug(f"已發送NAK: {nak_frame.hex()}")
                    
        except socket.timeout:
            self.logger.warning("接收資料超時")
        except Exception as e:
            self.logger.error(f"處理客戶端資料時發生錯誤: {e}", exc_info=True)
        finally:
            client_socket.close()
            self.logger.info(f"客戶端 {client_ip}:{client_port} 連線已關閉")
            
    def create_ack_frame(self, seq: int, addr: int) -> bytes:
        """建立ACK回應框"""
        self.logger.debug(f"建立ACK回應框: seq={seq}, addr={addr}")
        frame = bytearray([
            self.parser.DLE,
            self.parser.ACK,
            seq
        ])
        frame.extend(struct.pack('>H', addr))  # 2 bytes address
        frame.extend(struct.pack('>H', 8))  # LEN = 8 (含 CKS)
        cks = self.parser.calculate_cks(frame, 'ack')
        frame.append(cks)
        self.logger.debug(f"ACK回應框內容: {frame.hex()}")
        return bytes(frame)
        
    def create_nak_frame(self, seq: int, addr: int, err_code: int) -> bytes:
        """建立NAK回應框"""
        self.logger.debug(f"建立NAK回應框: seq={seq}, addr={addr}, err_code={err_code}")
        frame = bytearray([
            self.parser.DLE,
            self.parser.NAK,
            seq
        ])
        frame.extend(struct.pack('>H', addr))  # 2 bytes address
        frame.extend(struct.pack('>H', 9))  # LEN = 9 (含 CKS)
        frame.append(err_code)  # 錯誤碼
        cks = self.parser.calculate_cks(frame, 'nak')
        frame.append(cks)
        self.logger.debug(f"NAK回應框內容: {frame.hex()}")
        return bytes(frame)
        
    def process_message(self, frame: dict) -> Optional[bytes]:
        """處理解析後的訊息並產生回應"""
        try:
            # 如果是 ACK 訊息，直接回傳 None（不需要處理）
            if frame.get('info') == b'':
                self.logger.debug("收到 ACK 訊息，不需要處理")
                return None
                
            # 解析訊息類型
            msg_info = self.parser.parse_message_type(frame['info'])
            if not msg_info:
                self.logger.error("無法解析訊息類型")
                return None
                
            msg_type = msg_info['type']
            msg_code = msg_info['code']
            msg_data = msg_info['data']
            
            self.logger.info(f"處理訊息: 類型={msg_type:02X}H, 代碼={msg_code:02X}H, 資料={msg_data.hex()}")
            
            # 根據訊息類型處理
            if msg_type == 0x0F:  # 基本訊息
                self.logger.debug("處理基本訊息")
                response = self._handle_basic_message(msg_code, msg_data, frame['seq'])
                if response is None:
                    self.logger.warning(f"基本訊息處理未產生回應: 代碼={msg_code:02X}H")
                return response
            elif msg_type == 0x5F:  # 號誌控制器訊息
                self.logger.debug("處理號誌控制器訊息")
                response = self._handle_signal_message(msg_code, msg_data)
                if response is None:
                    self.logger.warning(f"號誌控制器訊息處理未產生回應: 代碼={msg_code:02X}H")
                return response
            elif msg_type == 0x6F:  # 車輛偵測器訊息
                self.logger.debug("處理車輛偵測器訊息")
                response = self._handle_detector_message(msg_code, msg_data)
                if response is None:
                    self.logger.warning(f"車輛偵測器訊息處理未產生回應: 代碼={msg_code:02X}H")
                return response
            else:
                self.logger.warning(f"未知的訊息類型: {msg_type:02X}H")
                return None
                
        except Exception as e:
            self.logger.error(f"處理訊息時發生錯誤: {e}", exc_info=True)
            return None
            
    def _create_setting_response(self, command_id: bytes, seq: int) -> bytes:
        """建立設定回報訊息 (0F H+80 H)
        
        Args:
            command_id: 2 bytes 的 CommandID，第一個 byte 為設備碼，第二個 byte 為指令碼
            seq: 序號，必須與接收到的訊息序號相同
            
        Returns:
            bytes: 設定回報訊息
        """
        self.logger.info("建立設定回報訊息")
        if len(command_id) != 2:
            self.logger.warning("CommandID 長度必須為 2 bytes")
            return None
            
        self.logger.debug(f"設定回報的 CommandID: {command_id.hex()}")
        self.logger.debug(f"使用序號: {seq}")
        
        # 建立設定回報訊息 (0F H+80 H)
        # 格式：DLE+STX+SEQ+ADDR+LEN+0F+80+CommandID+DLE+ETX+CKS
        response = bytearray([
            self.parser.DLE,  # DLE
            self.parser.STX,  # STX
            seq,             # SEQ (使用接收到的序號)
            0x00, 0x01,      # ADDR
            0x00, 0x0E,      # LEN = 14 (含 CKS)
            0x0F, 0x80,      # 0F H+80 H
            command_id[0],    # 設備碼
            command_id[1],    # 指令碼
            self.parser.DLE,  # DLE
            self.parser.ETX   # ETX
        ])
        
        # 計算CKS
        cks = self.parser.calculate_cks(response, 'normal')
        response.append(cks)
        
        # 驗證回應格式
        expected_format = f"aa bb {seq:02x} 00 01 00 0e 0f 80 {command_id[0]:02x} {command_id[1]:02x} aa cc"
        actual_format = ' '.join([f"{b:02x}" for b in response])
        self.logger.debug(f"設定回報訊息格式驗證:")
        self.logger.debug(f"預期格式: {expected_format}")
        self.logger.debug(f"實際格式: {actual_format}")
        
        return bytes(response)

    def _handle_basic_message(self, msg_code: int, msg_data: bytes, seq: int) -> Optional[bytes]:
        """處理基本訊息"""
        self.logger.debug(f"處理基本訊息: msg_code={msg_code:02X}H, msg_data={msg_data.hex()}, seq={seq}")
        
        if msg_code == 0x10:  # 重啟設備訊息
            self.logger.info("處理重啟設備訊息")
            # 建立重啟回報訊息 (0F H+90 H)
            response = bytearray([
                self.parser.DLE,
                self.parser.STX,
                seq,            # 使用接收到的序號
                0x00, 0x01,     # ADDR
                0x00, 0x0E,     # LEN = 14 (含 CKS)
                0x0F, 0x90,     # 0F H+90 H
                0x52, 0x52,     # Reset參數 (52H)
                self.parser.DLE,
                self.parser.ETX
            ])
            # 計算CKS
            cks = self.parser.calculate_cks(response, 'normal')
            response.append(cks)
            self.logger.debug(f"重啟回報訊息內容: {response.hex()}")
            return bytes(response)
            
        elif msg_code == 0x12:  # 設備日期、時間管理 設定
            self.logger.info("處理設備日期、時間管理設定訊息")
            
            # 檢查資料長度是否正確 (7 bytes: Year+Month+Day+Week+Hour+Min+Sec)
            if len(msg_data) != 7:
                self.logger.error(f"時間資料長度錯誤: {len(msg_data)}")
                return None
                
            # 解析時間資料
            year = msg_data[0]
            month = msg_data[1]
            day = msg_data[2]
            week = msg_data[3]
            hour = msg_data[4]
            minute = msg_data[5]
            second = msg_data[6]
            
            self.logger.info(f"收到時間設定: {year}年{month}月{day}日 星期{week} {hour:02d}:{minute:02d}:{second:02d}")
            
            # 驗證時間參數
            if not (1 <= month <= 12 and 1 <= day <= 31 and 1 <= week <= 7 and 
                   0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
                self.logger.error(f"時間參數無效: 月={month}, 日={day}, 星期={week}, 時={hour}, 分={minute}, 秒={second}")
                return None
                
            # 計算與系統時間的誤差
            current_time = time.localtime()
            time_diff = abs(
                (hour * 3600 + minute * 60 + second) - 
                (current_time.tm_hour * 3600 + current_time.tm_min * 60 + current_time.tm_sec)
            )
            
            self.logger.info(f"系統時間: {current_time.tm_hour:02d}:{current_time.tm_min:02d}:{current_time.tm_sec:02d}")
            self.logger.info(f"時間誤差: {time_diff}秒")
            
            # 如果誤差超過3秒，發送0F H+92 H
            if time_diff > 3:
                self.logger.info(f"時間誤差超過3秒: {time_diff}秒，發送0F H+92 H")
                response = bytearray([
                    self.parser.DLE,
                    self.parser.STX,
                    seq,            # 使用接收到的序號
                    0x00, 0x01,     # ADDR
                    0x00, 0x0E,     # LEN = 14 (含 CKS)
                    0x0F, 0x92,     # 0F H+92 H
                    min(time_diff, 128),  # SecDif (最大128)
                    self.parser.DLE,
                    self.parser.ETX
                ])
            else:
                # 誤差在3秒內，發送0F H+80 H
                self.logger.info("時間設定成功，發送0F H+80 H")
                return self._create_setting_response(bytes([0x0F, 0x12]), seq)
                
            # 計算CKS
            cks = self.parser.calculate_cks(response, 'normal')
            response.append(cks)
            self.logger.debug(f"時間設定回應訊息內容: {response.hex()}")
            return bytes(response)
            
        self.logger.warning(f"未知的基本訊息代碼: {msg_code:02X}H")
        return None
        
    def _handle_signal_message(self, msg_code: int, msg_data: bytes) -> Optional[bytes]:
        """處理號誌控制器訊息"""
        self.logger.debug(f"處理號誌控制器訊息: msg_code={msg_code:02X}H, msg_data={msg_data.hex()}")
        # TODO: 實作號誌控制器訊息處理邏輯
        return None
        
    def _handle_detector_message(self, msg_code: int, msg_data: bytes) -> Optional[bytes]:
        """處理車輛偵測器訊息"""
        self.logger.debug(f"處理車輛偵測器訊息: msg_code={msg_code:02X}H, msg_data={msg_data.hex()}")
        # TODO: 實作車輛偵測器訊息處理邏輯
        return None

def main():
    # 設定logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 啟動伺服器
    server = NTCIPServer()
    server.start()

if __name__ == '__main__':
    main() 