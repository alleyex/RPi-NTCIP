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
            
        校驗和計算方式：
        - 一般資料框：XOR(DLE, STX, SEQ, ADD, LEN, INFO, DLE, ETX)
        - ACK：XOR(DLE, ACK, SEQ, ADD, LEN)
        - NAK：XOR(DLE, NAK, SEQ, ADD, LEN, ERR)
        """
        self.logger.debug(f"計算校驗和: frame_type={frame_type}, data={data.hex()}")
        
        if frame_type == 'normal':
            # 一般訊息：XOR(DLE, STX, SEQ, ADD, LEN, INFO, DLE, ETX)
            return self._xor_bytes(data)
        elif frame_type == 'ack':
            # ACK：XOR(DLE, ACK, SEQ, ADD, LEN)
            return self._xor_bytes(data)
        elif frame_type == 'nak':
            # NAK：XOR(DLE, NAK, SEQ, ADD, LEN, ERR)
            return self._xor_bytes(data)
        else:
            raise ValueError(f"未知的資料框類型: {frame_type}")
            
    def _xor_bytes(self, data: bytes) -> int:
        """對位元組序列進行 XOR 運算"""
        cks = 0
        for byte in data:
            cks ^= byte
        self.logger.debug(f"XOR 運算結果: {cks:02x}")
        return cks
        
    def parse_frame(self, data: bytes) -> Optional[Dict]:
        """解析資料框"""
        self.logger.debug(f"開始解析資料框，原始資料: {data.hex()}")
        self.logger.debug(f"資料長度: {len(data)} bytes")
        
        if len(data) < 6:  # 最小長度檢查
            self.logger.error(f"資料長度不足: {len(data)} < 6")
            return None
        
        # 檢查起始碼
        if data[0] != self.DLE:
            self.logger.error(f"起始碼錯誤: {data[0]:02x} != {self.DLE:02x}")
            return None
            
        # 根據第二個位元組判斷資料框類型
        if data[1] == self.STX:  # 一般資料框
            self.logger.info("解析一般資料框")
            return self._parse_normal_frame(data)
        elif data[1] == self.ACK:  # ACK
            self.logger.info("解析ACK資料框")
            return self._parse_ack_frame(data)
        elif data[1] == self.NAK:  # NAK
            self.logger.info("解析NAK資料框")
            return self._parse_nak_frame(data)
        else:
            self.logger.error(f"未知的資料框類型: {data[1]:02x}")
            return None
            
    def _parse_normal_frame(self, data: bytes) -> Optional[Dict]:
        """解析一般資料框"""
        # 解析長度欄位
        length = (data[5] << 8) | data[6]
        self.logger.debug(f"解析到的長度欄位: {length}")
        self.logger.debug(f"資料框內容: {' '.join([f'{b:02x}' for b in data])}")
        
        # 檢查資料長度
        if len(data) < length:  # 確保資料長度足夠
            self.logger.error(f"資料長度不足: 預期 {length}, 實際 {len(data)}")
            self.logger.debug(f"資料內容: {' '.join([hex(b) for b in data])}")
            return None
            
        # 檢查結尾碼
        if data[length-3] != self.DLE or data[length-2] != self.ETX:
            self.logger.error(f"結尾碼錯誤: DLE={hex(data[length-3])}, ETX={hex(data[length-2])}")
            return None
            
        # 檢查校驗和
        cks = self.calculate_cks(data[:-1], 'normal')
        if cks != data[-1]:
            self.logger.error(f"校驗和錯誤: 預期 {hex(cks)}, 實際 {hex(data[-1])}")
            return None
            
        # 解析資料框內容
        info = data[7:length-3]  # 從INFO開始到DLE ETX之前（排除 DLE, ETX, CKS）
        self.logger.debug(f"解析到的 info 欄位: {info.hex()}")
        self.logger.debug(f"info 欄位長度: {len(info)} bytes")
        
        return {
            'seq': data[2],
            'addr': (data[3] << 8) | data[4],
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
        """解析負認知碼框格式
        
        格式：DLE + NAK + SEQ + ADDR(2) + LEN(2) + ERR + CKS
        DLE = 0xAA
        NAK = 0xEE
        LEN = 9 (固定長度)
        """
        self.logger.debug(f"開始解析 NAK 資料框: {data.hex()}")
        
        if len(data) != 9:  # DLE + NAK + SEQ + ADDR(2) + LEN(2) + ERR + CKS
            self.logger.error(f"NAK 資料框長度錯誤: {len(data)} != 9")
            return None
            
        # 檢查起始碼
        if data[0] != self.DLE or data[1] != self.NAK:
            self.logger.error(f"NAK 起始碼錯誤: DLE={data[0]:02x}, NAK={data[1]:02x}")
            return None
            
        seq = data[2]
        addr = struct.unpack('>H', data[3:5])[0]  # 2 bytes address
        length = struct.unpack('>H', data[5:7])[0]  # 2 bytes length
        
        if length != 9:
            self.logger.error(f"NAK 長度欄位錯誤: {length} != 9")
            return None
            
        err = data[7]  # 錯誤碼
        
        # 檢查錯誤碼是否有效
        if err not in [0x01, 0x02, 0x04, 0x08]:
            self.logger.error(f"NAK 錯誤碼無效: {err:02x}")
            return None
            
        # 計算校驗和
        received_cks = data[-1]
        calculated_cks = self.calculate_cks(data[:-1], 'nak')
        
        if received_cks != calculated_cks:
            self.logger.error(f"NAK 校驗和錯誤: 預期 {calculated_cks:02x}, 實際 {received_cks:02x}")
            return None
            
        self.logger.debug(f"NAK 解析結果: seq={seq:02x}, addr={addr:04x}, err={err:02x}")
        
        return {
            'seq': seq,
            'addr': addr,
            'length': length,
            'info': bytes([err])  # NAK 的 INFO 欄位包含錯誤碼
        }
        
    def parse_message_type(self, info: bytes) -> Optional[Dict]:
        """解析訊息類型"""
        self.logger.debug(f"開始解析訊息類型，info 內容: {info.hex()}")
        self.logger.debug(f"info 長度: {len(info)} bytes")
        
        if len(info) < 2:
            self.logger.error(f"info 長度不足: {len(info)} < 2")
            return None
            
        msg_type = info[0]
        msg_code = info[1]
        
        self.logger.debug(f"解析結果: 訊息類型={msg_type:02x}H, 訊息代碼={msg_code:02x}H")
        self.logger.debug(f"剩餘資料: {info[2:].hex()}")
        
        return {
            'type': msg_type,
            'code': msg_code,
            'data': info[2:]
        } 