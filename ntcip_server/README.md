# NTCIP TCP Server

這是一個用於解析NTCIP通訊協定的TCP伺服器程式。

## 功能特點

- 支援NTCIP通訊協定解析
- TCP/IP通訊
- 完整的錯誤處理
- 詳細的日誌記錄
- 模組化設計

## 安裝需求

- Python 3.8+
- 相關套件請參考 `requirements.txt`

## 安裝方式

```bash
# 建立虛擬環境
python -m venv venv

# 啟動虛擬環境
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

# 安裝依賴套件
pip install -r requirements.txt
```

## 使用方式

```bash
# 啟動伺服器
python -m src.ntcip_server
```

## 專案結構

```
ntcip_server/
├── README.md
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── ntcip_server.py
│   ├── ntcip_parser.py
│   └── utils/
│       ├── __init__.py
│       └── logger.py
├── tests/
│   ├── __init__.py
│   └── test_ntcip_server.py
└── config/
    └── config.yaml
```

## 開發者

- 作者：Your Name
- 版本：1.0.0
- 日期：2024-03-21

## 授權

MIT License 