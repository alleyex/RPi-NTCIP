import socket
import threading
import time
import pytest
import yaml
import os
from src.ntcip_parser import NTCIPParser
from src.ntcip_server import NTCIPServer

# 設定測試模式
os.environ['NTCIP_TEST_MODE'] = '1'

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
        0x00, 0x11,  # LEN (17 bytes = 包含 CKS 的總長度)
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
    test_frame = bytearray([
        0xAA, 0xBB,  # DLE, STX
        0x01,        # SEQ
        0x00, 0x01,  # ADDR
        0x00, 0x11,  # LEN (17 bytes = 包含 CKS 的總長度)
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
    assert result['length'] == 0x0011  # LEN = 0x11 (17 bytes, 含 CKS)
    assert len(result['info']) == 7
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
    assert result['length'] == 0x0008
    assert len(result['info']) == 0

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
        temp_data = bytearray(test_frame[:-1])
        cks = parser.calculate_cks(temp_data, 'nak')
        test_frame[-1] = cks
        
        result = parser.parse_frame(bytes(test_frame))
        assert result is not None, f"無法解析 {err_desc} 的 NAK 資料框"
        assert result['seq'] == 0x01
        assert result['addr'] == 0x0001
        assert result['length'] == 0x0009
        assert len(result['info']) == 1
        assert result['info'][0] == err_code

def test_tcp_data_handling():
    """測試TCP資料處理流程"""
    # 建立測試伺服器
    server = NTCIPServer(host='127.0.0.1', port=5001)
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # 等待伺服器啟動
    time.sleep(2)  # 增加等待時間確保伺服器完全啟動
    
    try:
        # 建立測試客戶端
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)  # 設定5秒超時
        client.connect(('127.0.0.1', 5001))
        
        # 建立測試資料框 (0F H+10 H 重啟設備訊息)
        test_frame = bytearray([
            0xAA, 0xBB,  # DLE, STX
            0x01,        # SEQ
            0x00, 0x01,  # ADDR
            0x00, 0x0E,  # LEN (14 bytes = 10+4, 含CKS)
            0x0F, 0x10,  # 0F H+10 H
            0x52, 0x52,  # Reset參數 (52H)
            0xAA, 0xCC,  # DLE, ETX
            0x00         # CKS (預設值)
        ])
        
        # 計算正確的CKS
        parser = NTCIPParser()
        cks = parser.calculate_cks(test_frame[:-1], 'normal')
        test_frame[-1] = cks
        
        # 發送測試資料
        client.send(bytes(test_frame))
        
        # 接收ACK
        ack_data = client.recv(1024)
        assert len(ack_data) == 8  # ACK 長度為 8 bytes
        assert ack_data[0] == 0xAA  # DLE
        assert ack_data[1] == 0xDD  # ACK
        assert ack_data[2] == 0x01  # SEQ
        
        # 等待並接收重啟回報訊息 (0F H+90 H)
        time.sleep(1)  # 等待設備重啟
        response = client.recv(1024)
        assert response is not None
        assert len(response) > 0
        assert response[0] == 0xAA  # DLE
        assert response[1] == 0xBB  # STX
        
        # 解析回應訊息
        parsed_response = parser.parse_frame(response)
        assert parsed_response is not None
        assert parsed_response['info'][0] == 0x0F  # 0F H
        assert parsed_response['info'][1] == 0x90  # 90 H
        
    except socket.timeout:
        pytest.fail("測試超時")
    except Exception as e:
        pytest.fail(f"測試失敗: {str(e)}")
    finally:
        # 清理
        client.close()
        server.stop()  # 確保伺服器關閉

def test_invalid_tcp_data():
    """測試無效TCP資料處理"""
    # 建立測試伺服器
    server = NTCIPServer(host='127.0.0.1', port=5002)
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # 等待伺服器啟動
    time.sleep(1)
    
    try:
        # 建立測試客戶端
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('127.0.0.1', 5002))
        
        # 發送無效資料
        invalid_data = bytes([0xAA, 0xCC])  # 無效的起始碼
        client.send(invalid_data)
        
        # 接收NAK
        nak_data = client.recv(1024)
        assert len(nak_data) == 9  # NAK 長度為 9 bytes
        assert nak_data[0] == 0xAA  # DLE
        assert nak_data[1] == 0xEE  # NAK
        assert nak_data[7] == 0x02  # 碼框錯誤
        
    finally:
        # 清理
        client.close()

def test_device_address_config():
    """測試裝置位址是否與設定檔相符"""
    # 讀取設定檔
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # 從設定檔獲取裝置位址
    config_addr = config['ntcip']['device']['address']
    
    # 建立測試資料框
    parser = NTCIPParser()
    test_frame = bytearray([
        0xAA, 0xBB,  # DLE, STX
        0x01,        # SEQ
        0x00, 0x01,  # ADDR (預設值)
        0x00, 0x11,  # LEN (17 bytes = 包含 CKS 的總長度)
        0x0F, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05,  # INFO
        0xAA, 0xCC,  # DLE, ETX
        0x00         # CKS (預設值)
    ])
    
    # 計算正確的CKS
    cks = parser.calculate_cks(test_frame[:-1], 'normal')
    test_frame[-1] = cks
    
    # 解析資料框
    result = parser.parse_frame(bytes(test_frame))
    
    # 驗證位址
    assert result is not None, "資料框解析失敗"
    assert result['addr'] == config_addr, f"裝置位址不符：預期 {hex(config_addr)}，實際 {hex(result['addr'])}"
    
    # 測試無效位址
    invalid_frame = bytearray(test_frame)
    invalid_frame[3] = 0xFF  # 修改為無效位址
    invalid_frame[4] = 0xFF
    
    # 重新計算CKS
    cks = parser.calculate_cks(invalid_frame[:-1], 'normal')
    invalid_frame[-1] = cks
    
    # 建立伺服器實例
    server = NTCIPServer(host='127.0.0.1', port=5003)
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # 等待伺服器啟動
    time.sleep(1)
    
    try:
        # 建立測試客戶端
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('127.0.0.1', 5003))
        
        # 發送無效位址的資料框
        client.send(bytes(invalid_frame))
        
        # 接收NAK
        nak_data = client.recv(1024)
        assert len(nak_data) == 9  # NAK 長度為 9 bytes
        assert nak_data[0] == 0xAA  # DLE
        assert nak_data[1] == 0xEE  # NAK
        assert nak_data[7] == 0x04  # 位址錯誤
        
    finally:
        # 清理
        client.close() 