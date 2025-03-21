import pyshark
import os
import time
import argparse
import binascii
from datetime import datetime
import shutil
from collections import deque
import sys
import signal

class PacketCapture:
    def __init__(self, ip1, ip2, interface=None):
        self.ip1 = ip1
        self.ip2 = ip2
        self.interface = interface
        self.max_packet_len = 117  # 最大パケット長（バイト）
        
        # 最新パケットを保存する変数（方向別）
        self.latest_hex_ip1_to_ip2 = ""
        self.timestamp_ip1_to_ip2 = None
        
        self.latest_hex_ip2_to_ip1 = ""
        self.timestamp_ip2_to_ip1 = None
        
        self.capture = None
        
        # ターミナルサイズの取得
        self.terminal_size = shutil.get_terminal_size()
        self.terminal_width = self.terminal_size.columns
        self.terminal_height = self.terminal_size.lines
        
        # 固定レイアウト用の行数計算
        self.header_lines = 4  # ヘッダー用行数
        self.section_header_lines = 3  # 各セクションのヘッダー行数
        self.section_footer_lines = 1  # 各セクションのフッター行数
        
        # 各セクションに割り当てる最大行数
        self.available_height = self.terminal_height - self.header_lines
        self.section_data_height = (self.available_height // 2) - self.section_header_lines - self.section_footer_lines
        
        # パケット表示用バッファ（各方向ごとに最新の表示行を保持）
        self.display_buffer_ip1_to_ip2 = []
        self.display_buffer_ip2_to_ip1 = []
        
        # 初期表示フラグ
        self.is_first_display = True
        
        # ANSI エスケープシーケンス
        self.CURSOR_UP = '\033[A'
        self.CURSOR_DOWN = '\033[B'
        self.CLEAR_LINE = '\033[2K'
        self.CURSOR_HOME = '\033[H'
        self.CLEAR_SCREEN = '\033[2J'
        self.CURSOR_SAVE = '\033[s'
        self.CURSOR_RESTORE = '\033[u'
        self.CURSOR_HIDE = '\033[?25l'
        self.CURSOR_SHOW = '\033[?25h'

    def setup_terminal(self):
        """ターミナルの設定と初期化"""
        # カーソルを非表示に
        print(self.CURSOR_HIDE, end='', flush=True)
        
        # 画面をクリア
        print(self.CLEAR_SCREEN + self.CURSOR_HOME, end='', flush=True)
        
        # シグナルハンドラの設定（Ctrl+C時にターミナルを元に戻す）
        signal.signal(signal.SIGINT, self.handle_interrupt)

    def handle_interrupt(self, sig, frame):
        """Ctrl+C時の処理"""
        self.cleanup_terminal()
        print("\nキャプチャを停止しました。")
        sys.exit(0)

    def cleanup_terminal(self):
        """ターミナルを元の状態に戻す"""
        # カーソルを表示
        print(self.CURSOR_SHOW, end='', flush=True)

    def start_capture(self):
        """パケットキャプチャを開始する"""
        # フィルタを設定：指定したIP間のUDPトラフィックのみ
        capture_filter = f"(host {self.ip1} and host {self.ip2}) and udp"
        
        # インターフェースが指定されている場合はそれを使用、それ以外はライブキャプチャ
        if self.interface:
            self.capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=capture_filter)
        else:
            self.capture = pyshark.LiveCapture(bpf_filter=capture_filter)
        
        try:
            # ターミナル設定
            self.setup_terminal()
            
            # 初期表示
            self._update_display()
            
            # スナップショットモードでキャプチャを開始
            for packet in self.capture.sniff_continuously():
                if hasattr(packet, 'udp') and hasattr(packet, 'ip'):
                    self._process_packet(packet)
        
        except KeyboardInterrupt:
            self.cleanup_terminal()
            print("\nキャプチャを停止しました。")
        except Exception as e:
            self.cleanup_terminal()
            print(f"エラーが発生しました: {e}")
        finally:
            self.cleanup_terminal()
            if self.capture:
                self.capture.close()
    
    def _process_packet(self, packet):
        """パケットを処理し表示する"""
        try:
            # パケット情報を抽出
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            
            # パケット長を取得
            updated = False
            if hasattr(packet.udp, 'payload'):
                udp_payload = packet.udp.payload
                # 16進数文字列からバイナリに変換
                udp_payload_hex = udp_payload.replace(':', '')
            else:
                udp_payload_hex = ""
            
            # パケットを方向に基づいて保存し、バッファを更新
            if src_ip == self.ip1 and dst_ip == self.ip2:
                self.latest_hex_ip1_to_ip2 = udp_payload_hex
                self.timestamp_ip1_to_ip2 = timestamp
                self._update_buffer_ip1_to_ip2()
                updated = True
            elif src_ip == self.ip2 and dst_ip == self.ip1:
                self.latest_hex_ip2_to_ip1 = udp_payload_hex
                self.timestamp_ip2_to_ip1 = timestamp
                self._update_buffer_ip2_to_ip1()
                updated = True
            
            # 画面表示を更新（パケットが更新された場合のみ）
            if updated:
                self._update_display()
            
        except Exception as e:
            self.cleanup_terminal()
            print(f"パケット処理エラー: {e}")
    
    def _update_buffer_ip1_to_ip2(self):
        """IP1->IP2方向のバッファを更新"""
        self.display_buffer_ip1_to_ip2 = self._format_hex_to_lines(self.latest_hex_ip1_to_ip2)
        
    def _update_buffer_ip2_to_ip1(self):
        """IP2->IP1方向のバッファを更新"""
        self.display_buffer_ip2_to_ip1 = self._format_hex_to_lines(self.latest_hex_ip2_to_ip1)
    
    def _format_hex_to_lines(self, hex_data):
        """16進数データを行のリストに変換"""
        lines = []
        if not hex_data:
            return ["データなし"]
            
        try:
            # バイナリデータに変換
            binary_data = binascii.unhexlify(hex_data)
            
            # 表示用バッファ
            offset = 0
            bytes_per_line = 16  # 1行に表示するバイト数
            
            while offset < len(binary_data):
                # 現在の行のバイト列
                line_bytes = binary_data[offset:offset + bytes_per_line]
                
                # オフセットを16進数で表示
                hex_offset = f"{offset:04x}"
                
                # バイト列を16進数文字列に変換
                hex_line = ' '.join([f"{b:02x}" for b in line_bytes])
                # 固定幅になるようにパディング
                hex_line = hex_line.ljust(bytes_per_line * 3 - 1)
                
                # ASCII表示用の文字列を生成
                ascii_line = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in line_bytes])
                
                # 行を追加
                lines.append(f"{hex_offset}:  {hex_line}  |  {ascii_line}")
                
                # オフセットを更新
                offset += bytes_per_line
                
            return lines
        
        except Exception as e:
            return [f"HEX表示エラー: {e}"]
    
    def _update_display(self):
        """両方向のパケット情報を表示する（ちらつき軽減版）"""
        # ターミナルサイズの更新（リサイズ対応）
        self.terminal_size = shutil.get_terminal_size()
        self.terminal_width = self.terminal_size.columns
        self.terminal_height = self.terminal_size.lines
        
        # 利用可能な高さの再計算
        self.available_height = self.terminal_height - self.header_lines
        self.section_data_height = (self.available_height // 2) - self.section_header_lines - self.section_footer_lines
        
        # 初回表示時は画面クリア、以降はカーソル位置調整のみ
        if self.is_first_display:
            print(self.CLEAR_SCREEN + self.CURSOR_HOME, end='', flush=True)
            self.is_first_display = False
        else:
            # カーソルを画面の先頭に移動
            print(self.CURSOR_HOME, end='', flush=True)
        
        # 表示内容をバッファに構築
        output_lines = []
        
        # ===== ヘッダー情報 =====
        output_lines.append(f"監視中: {self.ip1} <-> {self.ip2} (UDPのみ)")
        output_lines.append("Ctrl+Cで終了")
        output_lines.append("=" * self.terminal_width)
        
        # ===== 方向1のセクション =====
        output_lines.append(f"【方向1】: {self.ip1} -> {self.ip2}")
        
        if self.timestamp_ip1_to_ip2:
            output_lines.append(f"最終更新: {self.timestamp_ip1_to_ip2}")
            
            if self.latest_hex_ip1_to_ip2:
                length = len(binascii.unhexlify(self.latest_hex_ip1_to_ip2))
                output_lines.append(f"パケット長: {length} バイト")
                
                # 表示データの範囲を制限
                data_lines = self.display_buffer_ip1_to_ip2[:self.section_data_height]
                
                # データ行を追加
                output_lines.extend(data_lines)
                
                # 足りない行を空白で埋める
                for _ in range(self.section_data_height - len(data_lines)):
                    output_lines.append("")
            else:
                output_lines.append("パケットデータなし")
                # 残りの行を空白で埋める
                for _ in range(self.section_data_height):
                    output_lines.append("")
        else:
            output_lines.append("パケット未受信")
            # 残りの行を空白で埋める
            for _ in range(self.section_data_height + 1):
                output_lines.append("")
        
        # セクション間の区切り線
        output_lines.append("=" * self.terminal_width)
        
        # ===== 方向2のセクション =====
        output_lines.append(f"【方向2】: {self.ip2} -> {self.ip1}")
        
        if self.timestamp_ip2_to_ip1:
            output_lines.append(f"最終更新: {self.timestamp_ip2_to_ip1}")
            
            if self.latest_hex_ip2_to_ip1:
                length = len(binascii.unhexlify(self.latest_hex_ip2_to_ip1))
                output_lines.append(f"パケット長: {length} バイト")
                
                # 表示データの範囲を制限
                data_lines = self.display_buffer_ip2_to_ip1[:self.section_data_height]
                
                # データ行を追加
                output_lines.extend(data_lines)
                
                # 足りない行を空白で埋める
                for _ in range(self.section_data_height - len(data_lines)):
                    output_lines.append("")
            else:
                output_lines.append("パケットデータなし")
                # 残りの行を空白で埋める
                for _ in range(self.section_data_height):
                    output_lines.append("")
        else:
            output_lines.append("パケット未受信")
            # 残りの行を空白で埋める
            for _ in range(self.section_data_height + 1):
                output_lines.append("")
        
        # 画面に表示（行ごとにクリアしてから表示）
        for i, line in enumerate(output_lines):
            # 現在の行をクリア
            print(self.CLEAR_LINE, end='')
            # 行内容を表示
            print(line)
            
        # カーソルを先頭に戻す
        print(self.CURSOR_HOME, end='', flush=True)

def main():
    parser = argparse.ArgumentParser(description='ちらつき軽減型双方向UDPパケットキャプチャツール')
    parser.add_argument('--ip1', required=True, help='監視するIPアドレス1')
    parser.add_argument('--ip2', required=True, help='監視するIPアドレス2')
    parser.add_argument('--interface', help='使用するネットワークインターフェース（オプション）')
    
    args = parser.parse_args()
    
    # パケットキャプチャを初期化して開始
    capture = PacketCapture(args.ip1, args.ip2, args.interface)
    capture.start_capture()

if __name__ == "__main__":
    main()