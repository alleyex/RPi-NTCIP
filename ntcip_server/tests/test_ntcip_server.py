from src.ntcip_parser import NTCIPParser
from src.ntcip_server import NTCIPServer

def test_parser_initialization():
    """測試解析器初始化"""
    parser = NTCIPParser()
    assert parser.DLE == 0xAA
    assert parser.STX == 0xBB
    assert parser.ETX == 0xCC
    assert parser.ACK == 0xDD
    assert parser.NAK == 0xEE

def test_calculate_cks():
    """測試校驗和計算"""
    parser = NTCIPParser()
    # 建立一個完整的資料框進行測試
    test_data = bytes([
        0xAA, 0xBB,  # DLE, STX
        0x01,        # SEQ
        0x00, 0x01,  # ADDR
        0x00, 0x10,  # LEN (16 bytes = 不包含 CKS 的總長度)
        0x0F, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05,  # INFO (7 bytes)
        0xAA, 0xCC   # DLE, ETX
    ])
    cks = parser.calculate_cks(test_data, 'normal')
    assert isinstance(cks, int)
    assert 0 <= cks <= 255
    # 驗證CKS計算結果
    expected_cks = parser._xor_bytes(test_data)
    assert cks == expected_cks

def test_parse_frame_valid():
    """測試有效資料框解析"""
    parser = NTCIPParser()
    # 建立一個有效的測試資料框
    # 總長度 = DLE(1) + STX(1) + SEQ(1) + ADDR(2) + LEN(2) + INFO(7) + DLE(1) + ETX(1) + CKS(1) = 17 bytes
    # LEN = DLE(1) + STX(1) + SEQ(1) + ADDR(2) + LEN(2) + INFO(7) + DLE(1) + ETX(1) = 16 bytes
    test_frame = bytearray([
        0xAA, 0xBB,  # DLE, STX
        0x01,        # SEQ
        0x00, 0x01,  # ADDR
        0x00, 0x10,  # LEN (16 bytes = 不包含 CKS 的總長度)
        0x0F, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05,  # INFO (7 bytes)
        0xAA, 0xCC,  # DLE, ETX
        0x00         # CKS (預設值)
    ])
    
    # 計算正確的CKS
    cks = parser.calculate_cks(test_frame[:-1], 'normal')
    test_frame[-1] = cks
    
    result = parser.parse_frame(bytes(test_frame))
    assert result is not None
    assert result['seq'] == 0x01
    assert result['addr'] == 0x0001
    assert result['length'] == 0x0010  # 總長度 = 16 bytes (不包含 CKS)
    assert len(result['info']) == 7    # INFO 欄位長度為 7 bytes
    assert result['info'] == bytes([0x0F, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05])

def test_parse_frame_invalid():
    """測試無效資料框解析"""
    parser = NTCIPParser()
    # 測試資料長度不足
    assert parser.parse_frame(bytes([0xAA])) is None
    # 測試無效的起始碼
    assert parser.parse_frame(bytes([0xAA, 0xCC])) is None

def test_server_initialization():
    """測試伺服器初始化"""
    server = NTCIPServer(host='127.0.0.1', port=5000)
    assert server.host == '127.0.0.1'
    assert server.port == 5000
    assert server.server_socket is None

def test_parse_ack_frame():
    """測試正認知碼框(ACK)解析"""
    parser = NTCIPParser()
    # 建立一個有效的 ACK 資料框
    # ACK 格式: DLE + ACK + SEQ + ADDR + LEN + CKS
    test_frame = bytearray([
        0xAA,        # DLE
        0xDD,        # ACK
        0x01,        # SEQ
        0x00, 0x01,  # ADDR
        0x00, 0x08,  # LEN (8 bytes = 總長度)
        0x00         # CKS (預設值)
    ])
    
    # 計算正確的 CKS
    cks = parser.calculate_cks(test_frame[:-1], 'ack')
    test_frame[-1] = cks
    
    result = parser.parse_frame(bytes(test_frame))
    assert result is not None
    assert result['seq'] == 0x01
    assert result['addr'] == 0x0001
    assert result['length'] == 0x0008  # 總長度 = 8 bytes
    assert len(result['info']) == 0    # ACK 沒有 INFO 欄位

def test_parse_nak_frame():
    """測試負認知碼框(NAK)解析"""
    parser = NTCIPParser()
    
    # 測試不同的錯誤碼
    error_codes = {
        0x01: "校對位元錯誤",
        0x02: "碼框錯誤",
        0x04: "位址錯誤",
        0x08: "長度錯誤"
    }
    
    for err_code, err_desc in error_codes.items():
        # 建立一個有效的 NAK 資料框
        # NAK 格式: DLE + NAK + SEQ + ADDR + LEN + ERR + CKS
        test_frame = bytearray([
            0xAA,        # DLE
            0xEE,        # NAK
            0x01,        # SEQ
            0x00, 0x01,  # ADDR
            0x00, 0x09,  # LEN (9 bytes = 總長度)
            err_code,    # ERR (錯誤碼)
            0x00         # CKS (預設值)
        ])
        
        # 計算正確的 CKS
        # CKS = XOR(DLE, NAK, SEQ, ADDR, LEN, ERR, ETX)
        # 建立一個臨時的資料框，包含 ETX 用於校驗和計算
        temp_data = bytearray(test_frame[:-1])
        temp_data.append(parser.ETX)
        cks = parser.calculate_cks(temp_data, 'nak')
        test_frame[-1] = cks
        
        result = parser.parse_frame(bytes(test_frame))
        assert result is not None, f"無法解析 {err_desc} 的 NAK 資料框"
        assert result['seq'] == 0x01
        assert result['addr'] == 0x0001
        assert result['length'] == 0x0009  # 總長度 = 9 bytes
        assert len(result['info']) == 1    # NAK 的 INFO 欄位包含錯誤碼
        assert result['info'][0] == err_code, f"錯誤碼不符: 預期 {err_code:02x}H ({err_desc})" 