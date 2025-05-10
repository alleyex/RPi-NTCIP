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
        self.logger = logging.getLogger('NTCIPServer')
        
    def start(self):
        """啟動TCP伺服器"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.logger.info(f"伺服器啟動於 {self.host}:{self.port}")
        
        while True:
            client_socket, address = self.server_socket.accept()
            self.logger.info(f"接受來自 {address} 的連線")
            self.handle_client(client_socket)
            
    def handle_client(self, client_socket: socket.socket):
        """處理客戶端連線"""
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                    
                # 解析資料框
                frame = self.parser.parse_frame(data)
                if frame:
                    # 發送ACK
                    ack_frame = self.create_ack_frame(frame['seq'], frame['addr'])
                    client_socket.send(ack_frame)
                    
                    # 處理訊息
                    self.process_message(frame)
                else:
                    # 發送NAK
                    nak_frame = self.create_nak_frame(0, 0)  # 使用預設值
                    client_socket.send(nak_frame)
                    
        except Exception as e:
            self.logger.error(f"處理客戶端時發生錯誤: {e}")
        finally:
            client_socket.close()
            
    def create_ack_frame(self, seq: int, addr: int) -> bytes:
        """建立ACK回應框"""
        frame = bytearray([
            self.parser.DLE,
            self.parser.ACK,
            seq
        ])
        frame.extend(struct.pack('>H', addr))  # 2 bytes address
        frame.extend(struct.pack('>H', 8))  # 固定長度8
        frame.append(self.parser.calculate_cks(frame))
        return bytes(frame)
        
    def create_nak_frame(self, seq: int, addr: int) -> bytes:
        """建立NAK回應框"""
        frame = bytearray([
            self.parser.DLE,
            self.parser.NAK,
            seq
        ])
        frame.extend(struct.pack('>H', addr))  # 2 bytes address
        frame.extend(struct.pack('>H', 9))  # 固定長度9
        frame.append(1)  # 錯誤碼
        frame.append(self.parser.calculate_cks(frame))
        return bytes(frame)
        
    def process_message(self, frame: dict):
        """處理解析後的訊息"""
        # 這裡可以根據訊息類型進行不同的處理
        self.logger.info(f"收到訊息: {frame}")

if __name__ == '__main__':
    # 設定logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 啟動伺服器
    server = NTCIPServer()
    server.start() 