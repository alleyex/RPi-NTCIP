import logging
import os
from datetime import datetime

def setup_logger(name: str, log_dir: str = 'logs') -> logging.Logger:
    """設定日誌記錄器"""
    # 建立日誌目錄
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    # 建立日誌檔案名稱
    log_file = os.path.join(log_dir, f'{name}_{datetime.now().strftime("%Y%m%d")}.log')
    
    # 建立logger
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # 建立檔案處理器
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    
    # 建立控制台處理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # 設定日誌格式
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # 添加處理器到logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger 