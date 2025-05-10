from src.ntcip_communication import NTCIPCommunication

def test_create_data_request():
    """測試建立 Data_request 訊息"""
    comm = NTCIPCommunication()
    
    # 測試參數
    seq = 0x01
    addr = 0x0001
    info = bytes([0x0F, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05])
    
    # 建立 Data_request
    frame = comm.create_data_request(seq, addr, info)
    
    # 驗證資料框
    assert len(frame) == 17  # 總長度 = 16 + 1 (CKS)
    assert frame[0] == 0xAA  # DLE
    assert frame[1] == 0xBB  # STX
    assert frame[2] == seq   # SEQ
    assert frame[3:5] == addr.to_bytes(2, 'big')  # ADDR
    assert frame[5:7] == (16).to_bytes(2, 'big')  # LEN (不包含 CKS)
    assert frame[7:-3] == info  # INFO
    assert frame[-3] == 0xAA  # DLE
    assert frame[-2] == 0xCC  # ETX
    
def test_create_ack():
    """測試建立 ACK 訊息"""
    comm = NTCIPCommunication()
    
    # 測試參數
    seq = 0x01
    addr = 0x0001
    
    # 建立 ACK
    frame = comm.create_ack(seq, addr)
    
    # 驗證資料框
    assert len(frame) == 8  # 總長度 = 8 bytes
    assert frame[0] == 0xAA  # DLE
    assert frame[1] == 0xDD  # ACK
    assert frame[2] == seq   # SEQ
    assert frame[3:5] == addr.to_bytes(2, 'big')  # ADDR
    assert frame[5:7] == (8).to_bytes(2, 'big')  # LEN
    
def test_create_nak():
    """測試建立 NAK 訊息"""
    comm = NTCIPCommunication()
    
    # 測試參數
    seq = 0x01
    addr = 0x0001
    err_code = 0x01  # 校對位元錯誤
    
    # 建立 NAK
    frame = comm.create_nak(seq, addr, err_code)
    
    # 驗證資料框
    assert len(frame) == 9  # 總長度 = 9 bytes
    assert frame[0] == 0xAA  # DLE
    assert frame[1] == 0xEE  # NAK
    assert frame[2] == seq   # SEQ
    assert frame[3:5] == addr.to_bytes(2, 'big')  # ADDR
    assert frame[5:7] == (9).to_bytes(2, 'big')  # LEN
    assert frame[7] == err_code  # ERR
    
def test_send_data_request():
    """測試傳送 Data_request 並等待回應"""
    comm = NTCIPCommunication()
    
    # 測試參數
    seq = 0x01
    addr = 0x0001
    info = bytes([0x0F, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05])
    
    # 測試傳送 Data_request
    # 注意：這個測試需要實際的通訊介面，所以目前只是框架
    success, response = comm.send_data_request(seq, addr, info)
    
    # 驗證結果
    assert success is False  # 因為沒有實際的通訊介面
    assert response is None 