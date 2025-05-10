import socket
import struct
import logging
import time
from typing import Optional, Tuple, List
from .ntcip_parser import NTCIPParser

class NTCIPServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 5000):
        self.parser = NTCIPParser()
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.logger = logging.getLogger('NTCIPServer')
        
    def start(self):
        """啟動TCP伺服器"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            self.logger.info(f"伺服器啟動於 {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    self.logger.info(f"接受來自 {address} 的連線")
                    self.handle_client(client_socket)
                except Exception as e:
                    if self.running:  # 只有在伺服器仍在運行時才記錄錯誤
                        self.logger.error(f"處理客戶端連線時發生錯誤: {e}")
        except Exception as e:
            self.logger.error(f"啟動伺服器時發生錯誤: {e}")
            raise
        finally:
            self.stop()
            
    def stop(self):
        """停止TCP伺服器"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                self.logger.error(f"關閉伺服器時發生錯誤: {e}")
            finally:
                self.server_socket = None
        self.logger.info("伺服器已停止")
        
    def handle_client(self, client_socket: socket.socket):
        """處理客戶端連線"""
        try:
            while True:
                # 接收資料
                data = client_socket.recv(1024)
                if not data:
                    self.logger.info("客戶端關閉連線")
                    break
                    
                self.logger.debug(f"收到原始資料: {data.hex()}")
                
                # 解析資料框
                frame = self.parser.parse_frame(data)
                if frame:
                    self.logger.info(f"成功解析資料框: {frame}")
                    
                    # 檢查位址是否有效
                    if frame['addr'] == 0xFFFF:  # 無效位址
                        self.logger.warning("無效的裝置位址")
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
                else:
                    self.logger.warning("資料框解析失敗")
                    # 發送NAK，使用預設值
                    nak_frame = self.create_nak_frame(0, 0, 0x02)  # 碼框錯誤
                    client_socket.send(nak_frame)
                    self.logger.debug(f"已發送NAK: {nak_frame.hex()}")
                    
        except socket.timeout:
            self.logger.warning("接收資料超時")
        except Exception as e:
            self.logger.error(f"處理客戶端資料時發生錯誤: {e}")
        finally:
            client_socket.close()
            self.logger.info("客戶端連線已關閉")
            
    def create_ack_frame(self, seq: int, addr: int) -> bytes:
        """建立ACK回應框"""
        frame = bytearray([
            self.parser.DLE,
            self.parser.ACK,
            seq
        ])
        frame.extend(struct.pack('>H', addr))  # 2 bytes address
        frame.extend(struct.pack('>H', 8))  # LEN = 8 (含 CKS)
        cks = self.parser.calculate_cks(frame, 'ack')
        frame.append(cks)
        return bytes(frame)
        
    def create_nak_frame(self, seq: int, addr: int, err_code: int) -> bytes:
        """建立NAK回應框"""
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
        return bytes(frame)
        
    def process_message(self, frame: dict) -> Optional[bytes]:
        """處理解析後的訊息並產生回應"""
        try:
            # 解析訊息類型
            msg_info = self.parser.parse_message_type(frame['info'])
            if not msg_info:
                self.logger.error("無法解析訊息類型")
                return None
                
            msg_type = msg_info['type']
            msg_code = msg_info['code']
            msg_data = msg_info['data']
            
            self.logger.info(f"處理訊息: 類型={msg_type:02X}H, 代碼={msg_code:02X}H")
            
            # 根據訊息類型處理
            if msg_type == 0x0F:  # 基本訊息
                return self._handle_basic_message(msg_code, msg_data)
            elif msg_type == 0x5F:  # 號誌控制器訊息
                return self._handle_signal_message(msg_code, msg_data)
            elif msg_type == 0x6F:  # 車輛偵測器訊息
                return self._handle_detector_message(msg_code, msg_data)
            else:
                self.logger.warning(f"未知的訊息類型: {msg_type:02X}H")
                return None
                
        except Exception as e:
            self.logger.error(f"處理訊息時發生錯誤: {e}")
            return None
            
    def _handle_basic_message(self, msg_code: int, msg_data: bytes) -> Optional[bytes]:
        """處理基本訊息"""
        if msg_code == 0x10:  # 重啟設備訊息
            # 建立重啟回報訊息 (0F H+90 H)
            response = bytearray([
                self.parser.DLE,
                self.parser.STX,
                0x01,  # SEQ
                0x00, 0x01,  # ADDR
                0x00, 0x0E,  # LEN = 14 (含 CKS)
                0x0F, 0x90,  # 0F H+90 H
                0x52, 0x52,  # Reset參數 (52H)
                self.parser.DLE,
                self.parser.ETX
            ])
            # 計算CKS
            cks = self.parser.calculate_cks(response, 'normal')
            response.append(cks)
            return bytes(response)
        return None
        
    def _handle_signal_message(self, msg_code: int, msg_data: bytes) -> Optional[bytes]:
        """處理號誌控制器訊息"""
        # TODO: 實作號誌控制器訊息處理邏輯
        return None
        
    def _handle_detector_message(self, msg_code: int, msg_data: bytes) -> Optional[bytes]:
        """處理車輛偵測器訊息"""
        # TODO: 實作車輛偵測器訊息處理邏輯
        return None

if __name__ == '__main__':
    # 設定logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 啟動伺服器
    server = NTCIPServer()
    server.start() 