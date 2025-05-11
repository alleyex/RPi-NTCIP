import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import struct
import logging
import time
import os
from datetime import datetime
from ntcip_parser import NTCIPParser

class ControlCenterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NTCIP 控制中心模擬器")
        self.root.geometry("800x600")
        
        # 初始化變數
        self.socket = None
        self.parser = NTCIPParser()
        self.sequence_number = 0
        self.is_connected = False
        
        # 建立 UI 元件
        self._create_widgets()
        
        # 設定 logging
        self._setup_logging()
        
        # 設定日誌顏色標籤
        self.log_text.tag_configure("INFO", foreground="black")
        self.log_text.tag_configure("DEBUG", foreground="blue")
        self.log_text.tag_configure("WARNING", foreground="orange")
        self.log_text.tag_configure("ERROR", foreground="red")
        
    def _setup_logging(self):
        """設定日誌記錄"""
        self.logger = logging.getLogger('ControlCenterGUI')
        self.logger.setLevel(logging.DEBUG)
        
        # 建立日誌目錄
        log_dir = 'logs'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # 一般日誌檔案
        general_handler = logging.FileHandler(os.path.join(log_dir, 'control_center.log'))
        general_handler.setLevel(logging.INFO)
        general_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
        general_handler.setFormatter(general_formatter)
        self.logger.addHandler(general_handler)
        
        # 通訊流程日誌檔案
        comm_handler = logging.FileHandler(os.path.join(log_dir, 'control_center_communication.log'))
        comm_handler.setLevel(logging.DEBUG)
        comm_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
        comm_handler.setFormatter(comm_formatter)
        self.logger.addHandler(comm_handler)
        
        # 控制台輸出
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
    def _create_widgets(self):
        """建立 UI 元件"""
        # 建立主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 連線設定區域
        connection_frame = ttk.LabelFrame(main_frame, text="連線設定", padding="5")
        connection_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(connection_frame, text="主機:").grid(row=0, column=0, padx=5)
        self.host_entry = ttk.Entry(connection_frame, width=15)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.grid(row=0, column=1, padx=5)
        
        ttk.Label(connection_frame, text="埠口:").grid(row=0, column=2, padx=5)
        self.port_entry = ttk.Entry(connection_frame, width=6)
        self.port_entry.insert(0, "5000")
        self.port_entry.grid(row=0, column=3, padx=5)
        
        self.connect_button = ttk.Button(connection_frame, text="連線", command=self._connect)
        self.connect_button.grid(row=0, column=4, padx=5)
        
        # 命令區域
        command_frame = ttk.LabelFrame(main_frame, text="命令", padding="5")
        command_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(command_frame, text="裝置位址:").grid(row=0, column=0, padx=5)
        self.addr_entry = ttk.Entry(command_frame, width=6)
        self.addr_entry.insert(0, "1")
        self.addr_entry.grid(row=0, column=1, padx=5)
        
        # 重啟命令按鈕
        self.reset_button = ttk.Button(command_frame, text="重啟設備", command=self._send_reset_command)
        self.reset_button.grid(row=0, column=2, padx=5)
        self.reset_button.state(['disabled'])

        # 新增 0F H+12 H 命令按鈕
        self.h12_button = ttk.Button(command_frame, text="0F H+12 H", command=self._send_h12_command)
        self.h12_button.grid(row=0, column=3, padx=5)
        self.h12_button.state(['disabled'])

        # 新增測試 NAK 按鈕
        self.test_nak_button = ttk.Button(command_frame, text="測試 NAK", command=self._send_test_nak)
        self.test_nak_button.grid(row=0, column=4, padx=5)
        self.test_nak_button.state(['disabled'])
        
        # 日誌區域
        log_frame = ttk.LabelFrame(main_frame, text="通訊日誌", padding="5")
        log_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, width=80)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 設定 grid 權重
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
    def _log(self, message: str, level: str = "INFO"):
        """記錄訊息到日誌區域"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {level}: {message}\n"
        
        # 插入文字並設定顏色標籤
        self.log_text.insert(tk.END, log_message, level)
        self.log_text.see(tk.END)
        
        # 同時記錄到檔案
        if level == "ERROR":
            self.logger.error(message)
        elif level == "WARNING":
            self.logger.warning(message)
        elif level == "DEBUG":
            self.logger.debug(message)
        else:
            self.logger.info(message)
            
    def _connect(self):
        """連接到伺服器"""
        if not self.is_connected:
            try:
                host = self.host_entry.get()
                port = int(self.port_entry.get())
                
                self.logger.info(f"嘗試連接到 {host}:{port}")
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(5)
                self.socket.connect((host, port))
                
                self.is_connected = True
                self.connect_button.configure(text="斷線")
                self.reset_button.state(['!disabled'])
                self.h12_button.state(['!disabled'])
                self.test_nak_button.state(['!disabled'])
                
                self._log(f"已連接到 {host}:{port}")
                self.logger.info(f"成功連接到 {host}:{port}")
                
            except Exception as e:
                error_msg = f"連線失敗: {str(e)}"
                self._log(error_msg, "ERROR")
                self.logger.error(error_msg, exc_info=True)
                messagebox.showerror("錯誤", error_msg)
                self._disconnect()
        else:
            self._disconnect()
            
    def _disconnect(self):
        """斷開與伺服器的連線"""
        if self.socket:
            try:
                self.socket.close()
                self.logger.info("已關閉 socket 連線")
            except Exception as e:
                self.logger.error(f"關閉 socket 時發生錯誤: {str(e)}", exc_info=True)
            finally:
                self.socket = None
                
        self.is_connected = False
        self.connect_button.configure(text="連線")
        self.reset_button.state(['disabled'])
        self.h12_button.state(['disabled'])
        self.test_nak_button.state(['disabled'])
        self._log("已斷開連線")
        self.logger.info("已斷開連線")
        
    def _create_data_request(self, addr: int, info: bytes) -> bytes:
        """建立資料請求框"""
        self.sequence_number = (self.sequence_number + 1) % 256
        
        # 計算總長度（包含 CKS）
        # DLE(1) + STX(1) + SEQ(1) + ADDR(2) + LEN(2) + INFO(n) + DLE(1) + ETX(1) + CKS(1)
        total_length = 10 + len(info)
        
        # 建立資料框
        frame = bytearray([
            self.parser.DLE,  # DLE
            self.parser.STX,  # STX
            self.sequence_number,  # SEQ
        ])
        
        # 加入位址（2 bytes）
        frame.extend(addr.to_bytes(2, 'big'))
        
        # 加入長度（2 bytes）- LEN 欄位包含 CKS
        frame.extend(total_length.to_bytes(2, 'big'))
        
        # 加入資訊欄位
        frame.extend(info)
        
        # 加入結束碼
        frame.extend([self.parser.DLE, self.parser.ETX])
        
        # 計算並加入校驗和
        cks = self.parser.calculate_cks(frame, 'normal')
        frame.append(cks)
        
        return bytes(frame)
        
    def _send_request(self, addr: int, msg_type: int, msg_code: int, data: bytes = b'') -> bool:
        """發送請求並等待回應"""
        if not self.is_connected:
            error_msg = "未連接到伺服器"
            self._log(error_msg, "ERROR")
            self.logger.error(error_msg)
            return False
            
        try:
            # 建立資訊欄位
            info = bytearray([msg_type, msg_code])
            info.extend(data)
            
            # 建立並發送請求
            request = self._create_data_request(addr, info)
            self.socket.send(request)
            
            # 記錄詳細的通訊資訊
            self._log(f"發送請求: {request.hex()}")
            self.logger.debug(f"發送請求: {request.hex()}")
            self._log(f"請求內容解析: 位址={addr}, 訊息類型=0x{msg_type:02X}, 訊息代碼=0x{msg_code:02X}, 資料={data.hex()}")
            self.logger.debug(f"請求內容解析: 位址={addr}, 訊息類型=0x{msg_type:02X}, 訊息代碼=0x{msg_code:02X}, 資料={data.hex()}")
            
            # 等待 ACK
            ack_data = self.socket.recv(1024)
            if not ack_data:
                error_msg = "未收到 ACK"
                self._log(error_msg, "ERROR")
                self.logger.error(error_msg)
                return False
                
            self._log(f"收到 ACK: {ack_data.hex()}")
            self.logger.debug(f"收到 ACK: {ack_data.hex()}")
            
            # 解析 ACK
            ack_frame = self.parser.parse_frame(ack_data)
            if not ack_frame:
                error_msg = "ACK 解析失敗"
                self._log(error_msg, "ERROR")
                self.logger.error(error_msg)
                
                # 發送 NAK 回應
                nak_frame = bytearray([
                    self.parser.DLE,
                    self.parser.NAK,
                    self.sequence_number
                ])
                nak_frame.extend(addr.to_bytes(2, 'big'))
                nak_frame.extend((9).to_bytes(2, 'big'))  # LEN = 9
                nak_frame.append(0x02)  # ERR = 2 (碼框錯誤)
                cks = self.parser.calculate_cks(nak_frame, 'nak')
                nak_frame.append(cks)
                self.socket.send(bytes(nak_frame))
                
                self._log(f"發送 NAK: {bytes(nak_frame).hex()}")
                self.logger.debug(f"發送 NAK: {bytes(nak_frame).hex()}")
                return False
                
            self._log(f"ACK 解析結果: {ack_frame}")
            self.logger.debug(f"ACK 解析結果: {ack_frame}")
            
            # 等待回應訊息
            response_data = self.socket.recv(1024)
            if not response_data:
                error_msg = "未收到回應訊息"
                self._log(error_msg, "ERROR")
                self.logger.error(error_msg)
                return False
                
            self._log(f"收到回應: {response_data.hex()}")
            self.logger.debug(f"收到回應: {response_data.hex()}")
            
            # 解析回應訊息
            response_frame = self.parser.parse_frame(response_data)
            if not response_frame:
                error_msg = "回應訊息解析失敗"
                self._log(error_msg, "ERROR")
                self.logger.error(error_msg)
                
                # 發送 NAK 回應
                nak_frame = bytearray([
                    self.parser.DLE,
                    self.parser.NAK,
                    self.sequence_number
                ])
                nak_frame.extend(addr.to_bytes(2, 'big'))
                nak_frame.extend((9).to_bytes(2, 'big'))  # LEN = 9
                nak_frame.append(0x02)  # ERR = 2 (碼框錯誤)
                cks = self.parser.calculate_cks(nak_frame, 'nak')
                nak_frame.append(cks)
                self.socket.send(bytes(nak_frame))
                
                self._log(f"發送 NAK: {bytes(nak_frame).hex()}")
                self.logger.debug(f"發送 NAK: {bytes(nak_frame).hex()}")
                return False
                
            self._log(f"回應訊息解析結果: {response_frame}")
            self.logger.debug(f"回應訊息解析結果: {response_frame}")
            
            # 解析回應資料
            if 'info' in response_frame:
                response_info = response_frame['info']
                if len(response_info) >= 2:
                    resp_msg_type = response_info[0]
                    resp_msg_code = response_info[1]
                    resp_data = response_info[2:] if len(response_info) > 2 else b''
                    
                    self._log(f"回應資料解析: 訊息類型=0x{resp_msg_type:02X}, 訊息代碼=0x{resp_msg_code:02X}, 資料={resp_data.hex()}")
                    self.logger.debug(f"回應資料解析: 訊息類型=0x{resp_msg_type:02X}, 訊息代碼=0x{resp_msg_code:02X}, 資料={resp_data.hex()}")
                    
                    # 檢查回應狀態
                    if resp_msg_type == 0x0F and resp_msg_code == 0x80:
                        self._log("收到設定回報訊息 (0F H+80 H)")
                        if len(resp_data) >= 2:
                            device_code = resp_data[0]
                            command_code = resp_data[1]
                            self._log(f"設定回報解析: 設備碼=0x{device_code:02X}, 指令碼=0x{command_code:02X}")
                    elif resp_msg_type == 0x0F and resp_msg_code == 0x81:
                        self._log("收到錯誤回報訊息 (0F H+81 H)")
                        if len(resp_data) >= 3:
                            device_code = resp_data[0]
                            command_code = resp_data[1]
                            error_code = resp_data[2]
                            param_number = resp_data[3] if len(resp_data) > 3 else 0
                            self._log(f"錯誤回報解析: 設備碼=0x{device_code:02X}, 指令碼=0x{command_code:02X}, 錯誤碼=0x{error_code:02X}, 參數編號={param_number}")
            
            # 發送 ACK 回應
            ack_frame = bytearray([
                self.parser.DLE,
                self.parser.ACK,
                response_frame['seq']
            ])
            ack_frame.extend(response_frame['addr'].to_bytes(2, 'big'))
            ack_frame.extend((8).to_bytes(2, 'big'))  # LEN = 8
            cks = self.parser.calculate_cks(ack_frame, 'ack')
            ack_frame.append(cks)
            self.socket.send(bytes(ack_frame))
            
            self._log(f"發送 ACK: {bytes(ack_frame).hex()}")
            self.logger.debug(f"發送 ACK: {bytes(ack_frame).hex()}")
            
            return True
            
        except Exception as e:
            error_msg = f"發送請求時發生錯誤: {str(e)}"
            self._log(error_msg, "ERROR")
            self.logger.error(error_msg, exc_info=True)
            return False
            
    def _send_reset_command(self):
        """發送重啟設備命令"""
        try:
            addr = int(self.addr_entry.get())
            success = self._send_request(addr, 0x0F, 0x10, bytes([0x52, 0x52]))
            
            if success:
                self._log("重啟命令已發送")
            else:
                self._log("重啟命令失敗", "ERROR")
                
        except ValueError:
            self._log("無效的裝置位址", "ERROR")
            messagebox.showerror("錯誤", "請輸入有效的裝置位址")

    def _send_h12_command(self):
        """發送 0F H+12 H 命令"""
        try:
            addr = int(self.addr_entry.get())
            self._log(f"準備發送 0F H+12 H 命令到裝置 {addr}")
            
            # 從系統時間獲取當前時間
            from datetime import datetime
            now = datetime.now()
            
            # 準備時間資料
            year = now.year % 100  # 取年份後兩位
            month = now.month
            day = now.day
            week = now.isoweekday()  # 1-7 (星期一-星期日)
            hour = now.hour
            minute = now.minute
            second = now.second
            
            # 建立時間資料位元組
            time_data = bytes([
                year,    # 年 (0-99)
                month,   # 月 (1-12)
                day,     # 日 (1-31)
                week,    # 星期 (1-7)
                hour,    # 時 (0-23)
                minute,  # 分 (0-59)
                second   # 秒 (0-59)
            ])
            
            # 發送命令
            success = self._send_request(addr, 0x0F, 0x12, time_data)
            
            if success:
                self._log("0F H+12 H 命令已成功發送")
                self._log(f"命令解析: 訊息類型=0x0F, 訊息代碼=0x12, 資料={time_data.hex()}")
                self._log(f"設定時間: {year+2000}年{month}月{day}日 星期{week} {hour:02d}:{minute:02d}:{second:02d}")
            else:
                self._log("0F H+12 H 命令發送失敗", "ERROR")
                
        except ValueError:
            self._log("無效的裝置位址", "ERROR")
            messagebox.showerror("錯誤", "請輸入有效的裝置位址")
        except Exception as e:
            self._log(f"發送 0F H+12 H 命令時發生錯誤: {str(e)}", "ERROR")
            messagebox.showerror("錯誤", f"發送命令時發生錯誤: {str(e)}")

    def _send_test_nak(self):
        """發送測試 NAK 的錯誤訊息"""
        try:
            addr = int(self.addr_entry.get())
            self._log(f"準備發送測試 NAK 訊息到裝置 {addr}")
            
            # 建立一個錯誤的訊息格式（故意設定錯誤的校驗和）
            frame = bytearray([
                self.parser.DLE,  # DLE
                self.parser.STX,  # STX
                self.sequence_number,  # SEQ
            ])
            
            # 加入位址（2 bytes）
            frame.extend(addr.to_bytes(2, 'big'))
            
            # 加入長度（2 bytes）- 故意設定錯誤的長度
            frame.extend((20).to_bytes(2, 'big'))  # 設定一個明顯錯誤的長度
            
            # 加入資訊欄位（0F H+10 H 重啟命令）
            frame.extend([0x0F, 0x10, 0x52, 0x52])
            
            # 加入結束碼
            frame.extend([self.parser.DLE, self.parser.ETX])
            
            # 故意設定錯誤的校驗和
            frame.append(0xFF)  # 錯誤的校驗和
            
            # 發送錯誤的訊息
            self.socket.send(bytes(frame))
            self._log(f"發送測試 NAK 訊息: {bytes(frame).hex()}")
            
            # 等待 NAK 回應
            response_data = self.socket.recv(1024)
            if not response_data:
                error_msg = "未收到 NAK 回應"
                self._log(error_msg, "ERROR")
                self.logger.error(error_msg)
                return
                
            self._log(f"收到回應: {response_data.hex()}")
            self.logger.debug(f"收到回應: {response_data.hex()}")
            
            # 解析 NAK 回應
            response_frame = self.parser.parse_frame(response_data)
            if not response_frame:
                error_msg = "NAK 回應解析失敗"
                self._log(error_msg, "ERROR")
                self.logger.error(error_msg)
                return
                
            self._log(f"NAK 回應解析結果: {response_frame}")
            self.logger.debug(f"NAK 回應解析結果: {response_frame}")
            
            # 檢查是否為 NAK 回應
            if 'info' in response_frame:
                error_code = response_frame['info'][0] if response_frame['info'] else None
                if error_code is not None:
                    self._log(f"收到錯誤回應，錯誤碼: 0x{error_code:02X}")
                    if error_code == 0x02:
                        self._log("錯誤原因：碼框錯誤")
                    elif error_code == 0x03:
                        self._log("錯誤原因：校驗和錯誤")
                    elif error_code == 0x04:
                        self._log("錯誤原因：長度錯誤")
                    else:
                        self._log(f"未知錯誤碼: 0x{error_code:02X}")
            
        except ValueError:
            self._log("無效的裝置位址", "ERROR")
            messagebox.showerror("錯誤", "請輸入有效的裝置位址")
        except Exception as e:
            self._log(f"發送測試 NAK 訊息時發生錯誤: {str(e)}", "ERROR")
            messagebox.showerror("錯誤", f"發送訊息時發生錯誤: {str(e)}")

def main():
    root = tk.Tk()
    app = ControlCenterGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main() 