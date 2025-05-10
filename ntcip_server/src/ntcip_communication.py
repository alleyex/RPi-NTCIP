import logging
from typing import Optional, Dict, Tuple
from .ntcip_parser import NTCIPParser

class NTCIPCommunication:
    def __init__(self):
        self.parser = NTCIPParser()
        self.logger = logging.getLogger('NTCIPCommunication')
        
    def create_data_request(self, seq: int, addr: int, info: bytes) -> bytes:
        """建立 Data_request 訊息
        
        Args:
            seq: 序號
            addr: 位址
            info: 資訊欄位
            
        Returns:
            bytes: 完整的資料框
        """
        # 計算總長度（不包含 CKS）
        # DLE(1) + STX(1) + SEQ(1) + ADDR(2) + LEN(2) + INFO(n) + DLE(1) + ETX(1)
        total_length = 9 + len(info)
        
        # 建立資料框
        frame = bytearray([
            self.parser.DLE,  # DLE
            self.parser.STX,  # STX
            seq,             # SEQ
        ])
        
        # 加入位址（2 bytes）
        frame.extend(addr.to_bytes(2, 'big'))
        
        # 加入長度（2 bytes）
        frame.extend(total_length.to_bytes(2, 'big'))
        
        # 加入資訊欄位
        frame.extend(info)
        
        # 加入結束碼
        frame.extend([self.parser.DLE, self.parser.ETX])
        
        # 計算並加入校驗和
        cks = self.parser.calculate_cks(frame, 'normal')
        frame.append(cks)
        
        return bytes(frame)
        
    def create_ack(self, seq: int, addr: int) -> bytes:
        """建立 ACK 訊息
        
        Args:
            seq: 序號
            addr: 位址
            
        Returns:
            bytes: 完整的 ACK 資料框
        """
        # 建立 ACK 資料框
        frame = bytearray([
            self.parser.DLE,  # DLE
            self.parser.ACK,  # ACK
            seq,             # SEQ
        ])
        
        # 加入位址（2 bytes）
        frame.extend(addr.to_bytes(2, 'big'))
        
        # 加入長度（2 bytes）
        frame.extend((8).to_bytes(2, 'big'))  # 8 bytes = DLE + ACK + SEQ + ADDR(2) + LEN(2) + CKS
        
        # 計算並加入校驗和
        cks = self.parser.calculate_cks(frame, 'ack')
        frame.append(cks)
        
        return bytes(frame)
        
    def create_nak(self, seq: int, addr: int, err_code: int) -> bytes:
        """建立 NAK 訊息
        
        Args:
            seq: 序號
            addr: 位址
            err_code: 錯誤碼
            
        Returns:
            bytes: 完整的 NAK 資料框
        """
        # 建立 NAK 資料框
        frame = bytearray([
            self.parser.DLE,  # DLE
            self.parser.NAK,  # NAK
            seq,             # SEQ
        ])
        
        # 加入位址（2 bytes）
        frame.extend(addr.to_bytes(2, 'big'))
        
        # 加入長度（2 bytes）
        frame.extend((9).to_bytes(2, 'big'))  # 9 bytes = DLE + NAK + SEQ + ADDR(2) + LEN(2) + ERR + CKS
        
        # 加入錯誤碼
        frame.append(err_code)
        
        # 計算並加入校驗和
        cks = self.parser.calculate_cks(frame, 'nak')
        frame.append(cks)
        
        return bytes(frame)
        
    def send_data_request(self, seq: int, addr: int, info: bytes) -> Tuple[bool, Optional[Dict]]:
        """傳送 Data_request 並等待回應
        
        Args:
            seq: 序號
            addr: 位址
            info: 資訊欄位
            
        Returns:
            Tuple[bool, Optional[Dict]]: (是否成功, 回應資料)
        """
        # 建立並傳送 Data_request
        request_frame = self.create_data_request(seq, addr, info)
        # TODO: 實際傳送資料的程式碼
        
        # 等待 ACK
        # TODO: 實際接收 ACK 的程式碼
        ack_frame = None  # 這裡應該要從通訊介面接收資料
        
        if ack_frame is None:
            self.logger.error("未收到 ACK")
            return False, None
            
        # 解析 ACK
        ack_result = self.parser.parse_frame(ack_frame)
        if ack_result is None:
            self.logger.error("ACK 解析失敗")
            return False, None
            
        # 檢查序號是否相符
        if ack_result['seq'] != seq:
            self.logger.error(f"序號不符: 預期 {seq}, 實際 {ack_result['seq']}")
            return False, None
            
        # 等待 Data_response
        # TODO: 實際接收 Data_response 的程式碼
        response_frame = None  # 這裡應該要從通訊介面接收資料
        
        if response_frame is None:
            self.logger.error("未收到 Data_response")
            return False, None
            
        # 解析 Data_response
        response_result = self.parser.parse_frame(response_frame)
        if response_result is None:
            self.logger.error("Data_response 解析失敗")
            return False, None
            
        # 檢查序號是否相符
        if response_result['seq'] != seq:
            self.logger.error(f"序號不符: 預期 {seq}, 實際 {response_result['seq']}")
            return False, None
            
        # 傳送 ACK
        ack_frame = self.create_ack(seq, addr)
        # TODO: 實際傳送 ACK 的程式碼
        
        return True, response_result 