import struct
import logging
from typing import Optional, Dict

class NTCIPParser:
    def __init__(self):
        # 定義控制碼
        self.DLE = 0xAA
        self.STX = 0xBB
        self.ETX = 0xCC
        self.ACK = 0xDD
        self.NAK = 0xEE
        
        # 設定logging
        self.logger = logging.getLogger('NTCIPParser')
        
    def calculate_cks(self, data: bytes, frame_type: str = 'normal') -> int:
        """計算校驗和
        
        Args:
            data: 資料框
            frame_type: 資料框類型 ('normal', 'ack', 'nak')
        """
        if frame_type == 'normal':
            # 一般訊息：XOR(DLE, STX, SEQ, ADD, LEN, INFO, DLE, ETX)
            return self._xor_bytes(data)
        elif frame_type == 'ack':
            # ACK：XOR(DLE, ACK, SEQ, ADD, LEN)
            return self._xor_bytes(data)
        elif frame_type == 'nak':
            # NAK：XOR(DLE, NAK, SEQ, ADD, LEN, ERR, ETX)
            return self._xor_bytes(data)
        else:
            raise ValueError(f"未知的資料框類型: {frame_type}")
            
    def _xor_bytes(self, data: bytes) -> int:
        """對位元組序列進行 XOR 運算"""
        cks = 0
        for byte in data:
            cks ^= byte
        return cks
        
    def parse_frame(self, data: bytes) -> Optional[Dict]:
        """解析資料框"""
        if len(data) < 8:  # 最小長度檢查
            self.logger.error("資料長度不足")
            return None
            
        # 檢查起始碼
        if data[0] != self.DLE:
            self.logger.error("無效的資料框起始碼")
            return None
            
        # 根據第二個位元組判斷訊息類型
        if data[1] == self.STX:
            # 一般訊息格式
            return self._parse_normal_frame(data)
        elif data[1] == self.ACK:
            # 正認知碼框格式
            return self._parse_ack_frame(data)
        elif data[1] == self.NAK:
            # 負認知碼框格式
            return self._parse_nak_frame(data)
        else:
            self.logger.error("無效的資料框類型")
            return None
            
    def _parse_normal_frame(self, data: bytes) -> Optional[Dict]:
        """解析一般訊息格式"""
        # 解析基本欄位
        seq = data[2]
        addr = struct.unpack('>H', data[3:5])[0]  # 2 bytes address
        length = struct.unpack('>H', data[5:7])[0]  # 2 bytes length
        
        # 檢查資料長度
        # length 欄位不包含 CKS，所以實際資料長度應該比 length 多 1
        if len(data) != length + 1:
            self.logger.error(f"資料長度不符: 預期 {length + 1}, 實際 {len(data)}")
            return None
            
        # 解析資訊欄位
        info = data[7:-3]  # 從固定頭部後開始，到 DLE+ETX+CKS 之前
        
        # 檢查結束碼
        if data[-3] != self.DLE or data[-2] != self.ETX:
            self.logger.error("無效的資料框結束碼")
            return None
            
        received_cks = data[-1]
        calculated_cks = self.calculate_cks(data[:-1], 'normal')
        
        if received_cks != calculated_cks:
            self.logger.error("校驗和錯誤")
            return None
            
        return {
            'seq': seq,
            'addr': addr,
            'length': length,
            'info': info
        }
        
    def _parse_ack_frame(self, data: bytes) -> Optional[Dict]:
        """解析正認知碼框格式"""
        if len(data) != 8:  # DLE + ACK + SEQ + ADDR(2) + LEN(2) + CKS
            self.logger.error("ACK 資料框長度錯誤")
            return None
            
        seq = data[2]
        addr = struct.unpack('>H', data[3:5])[0]  # 2 bytes address
        length = struct.unpack('>H', data[5:7])[0]  # 2 bytes length
        
        if length != 8:
            self.logger.error("ACK 長度欄位錯誤")
            return None
            
        received_cks = data[-1]
        calculated_cks = self.calculate_cks(data[:-1], 'ack')
        
        if received_cks != calculated_cks:
            self.logger.error("ACK 校驗和錯誤")
            return None
            
        return {
            'seq': seq,
            'addr': addr,
            'length': length,
            'info': bytes()  # ACK 沒有 INFO 欄位
        }
        
    def _parse_nak_frame(self, data: bytes) -> Optional[Dict]:
        """解析負認知碼框格式"""
        if len(data) != 9:  # DLE + NAK + SEQ + ADDR(2) + LEN(2) + ERR + CKS
            self.logger.error("NAK 資料框長度錯誤")
            return None
            
        seq = data[2]
        addr = struct.unpack('>H', data[3:5])[0]  # 2 bytes address
        length = struct.unpack('>H', data[5:7])[0]  # 2 bytes length
        
        if length != 9:
            self.logger.error("NAK 長度欄位錯誤")
            return None
            
        err = data[7]  # 錯誤碼
        
        # 計算校驗和時需要包含 ETX，但實際資料框中不包含
        received_cks = data[-1]
        # 建立一個臨時的資料框，包含 ETX 用於校驗和計算
        temp_data = bytearray(data[:-1])
        temp_data.append(self.ETX)
        calculated_cks = self.calculate_cks(temp_data, 'nak')
        
        if received_cks != calculated_cks:
            self.logger.error("NAK 校驗和錯誤")
            return None
            
        return {
            'seq': seq,
            'addr': addr,
            'length': length,
            'info': bytes([err])  # NAK 的 INFO 欄位包含錯誤碼
        }
        
    def parse_message_type(self, info: bytes) -> Optional[Dict]:
        """解析訊息類型"""
        if len(info) < 2:
            return None
            
        msg_type = info[0]
        msg_code = info[1]
        
        return {
            'type': msg_type,
            'code': msg_code,
            'data': info[2:]
        } 