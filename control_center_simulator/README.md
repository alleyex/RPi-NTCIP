# NTCIP 控制中心模擬器

這是一個用於測試 NTCIP 伺服器的圖形化控制中心模擬器。

## 功能特點

- 圖形化使用者介面
- 即時通訊日誌顯示
- 支援 NTCIP 通訊協定
- 可設定連線參數
- 支援重啟設備命令

## 安裝需求

- Python 3.8+
- tkinter (通常隨 Python 一起安裝)

## 安裝方式

```bash
# 建立虛擬環境（選擇性）
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

1. 啟動程式：
```bash
python main.py
```

2. 在連線設定區域輸入伺服器的主機位址和埠口
3. 點擊「連線」按鈕連接到伺服器
4. 在裝置位址欄位輸入目標裝置的位址
5. 點擊「重啟設備」按鈕發送重啟命令
6. 在通訊日誌區域查看通訊過程

## 注意事項

- 確保 NTCIP 伺服器已經啟動並可以接受連線
- 預設連線參數為 localhost:5000
- 所有通訊過程都會記錄在日誌區域 


新增更多 NTCIP 命令
加入命令參數設定
新增通訊記錄儲存功能
加入更多錯誤處理機制