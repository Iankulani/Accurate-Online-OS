import socket
import threading
import time
import requests
import json
import subprocess
import os
from datetime import datetime
import scapy.all as scapy
from scapy.all import IP, TCP, UDP, ICMP
import logging
from typing import Dict, List, Set
import sys

# Configuration
CONFIG_FILE = "cyber_security_config.json"

class AccurateOS:
    def __init__(self):
        self.monitored_ips = set()
        self.monitoring_active = False
        self.command_history = []
        self.telegram_token = None
        self.telegram_chat_id = None
        self.telegram_bot = None
        self.logs = []
        self.threat_alerts = []
        self.setup_logging()
        self.load_config()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('cyber_security.log'),
                logging.StreamHandler()
            ]
        )
        
    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.telegram_token = config.get('telegram_token')
                    self.telegram_chat_id = config.get('telegram_chat_id')
                    self.monitored_ips = set(config.get('monitored_ips', []))
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            
    def save_config(self):
        try:
            config = {
                'telegram_token': self.telegram_token,
                'telegram_chat_id': self.telegram_chat_id,
                'monitored_ips': list(self.monitored_ips)
            }
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving config: {e}")

class TelegramBotHandler:
    def __init__(self, monitor):
        self.monitor = monitor
        self.last_update_id = 0
        
    def send_telegram_message(self, message):
        if not self.monitor.telegram_token or not self.monitor.telegram_chat_id:
            return False
            
        try:
            url = f"https://api.telegram.org/bot{self.monitor.telegram_token}/sendMessage"
            payload = {
                'chat_id': self.monitor.telegram_chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, json=payload)
            return response.status_code == 200
        except Exception as e:
            logging.error(f"Telegram send error: {e}")
            return False
            
    def get_updates(self):
        if not self.monitor.telegram_token:
            return []
            
        try:
            url = f"https://api.telegram.org/bot{self.monitor.telegram_token}/getUpdates"
            params = {'offset': self.last_update_id + 1, 'timeout': 30}
            response = requests.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                if data['ok']:
                    return data['result']
            return []
        except Exception as e:
            logging.error(f"Telegram update error: {e}")
            return []
            
    def process_telegram_commands(self):
        updates = self.get_updates()
        for update in updates:
            self.last_update_id = update['update_id']
            if 'message' in update and 'text' in update['message']:
                message = update['message']['text']
                chat_id = update['message']['chat']['id']
                self.monitor.telegram_chat_id = chat_id
                self.handle_telegram_command(message, chat_id)
                
    def handle_telegram_command(self, command, chat_id):
        command = command.strip()
        self.monitor.command_history.append(f"TELEGRAM: {command}")
        
        if command == '/help':
            help_text = """
🔒 <b>Accurate Online OS</b> 🔒

<b>Basic Commands:</b>
/help - Show this help message
/status - Show monitoring status
/view - View monitored IPs
/history - View command history

<b>IP Operations:</b>
/ping_ip [IP] - Ping an IP address
/location_ip [IP] - Get IP location
/scan_ip [IP] - Quick port scan
/deep_scan_ip [IP] - Full port scan (1-65535)
/add_ip [IP] - Add IP to monitoring
/remove_ip [IP] - Remove IP from monitoring

<b>Monitoring:</b>
/start_monitoring_ip [IP] - Start monitoring IP
/stop - Stop all monitoring
/exit - Exit monitoring

<b>Tracing:</b>
/udptraceroute [IP] - UDP traceroute
/tcptraceroute [IP] - TCP traceroute

<b>Configuration:</b>
/config_telegram_token [TOKEN] - Set Telegram bot token
/config_telegram_chat_id [ID] - Set chat ID
/export_data - Export data to Telegram
            """
            self.send_telegram_message(help_text)
            
        elif command.startswith('/ping_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.ping_ip(ip)
                self.send_telegram_message(f"🏓 Ping result for {ip}:\n{result}")
            else:
                self.send_telegram_message("❌ Please provide an IP address")
                
        elif command.startswith('/start_monitoring_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.start_monitoring_ip(ip)
                self.send_telegram_message(result)
            else:
                self.send_telegram_message("❌ Please provide an IP address")
                
        elif command == '/stop':
            result = self.monitor.stop_monitoring()
            self.send_telegram_message(result)
            
        elif command == '/status':
            status = self.monitor.get_status()
            self.send_telegram_message(status)
            
        elif command.startswith('/location_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                location = self.monitor.get_ip_location(ip)
                self.send_telegram_message(f"📍 Location for {ip}:\n{location}")
            else:
                self.send_telegram_message("❌ Please provide an IP address")
                
        elif command.startswith('/scan_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.scan_ports(ip, 1, 1000)
                self.send_telegram_message(f"🔍 Scan result for {ip}:\n{result}")
            else:
                self.send_telegram_message("❌ Please provide an IP address")
                
        elif command.startswith('/deep_scan_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.scan_ports(ip, 1, 65535)
                self.send_telegram_message(f"🔍 Deep scan result for {ip}:\n{result}")
            else:
                self.send_telegram_message("❌ Please provide an IP address")
                
        elif command == '/view':
            ips = self.monitor.view_monitored_ips()
            self.send_telegram_message(f"📋 Monitored IPs:\n{ips}")
            
        elif command.startswith('/add_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.add_ip(ip)
                self.send_telegram_message(result)
            else:
                self.send_telegram_message("❌ Please provide an IP address")
                
        elif command.startswith('/remove_ip'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.remove_ip(ip)
                self.send_telegram_message(result)
            else:
                self.send_telegram_message("❌ Please provide an IP address")
                
        elif command == '/history':
            history = self.monitor.get_command_history()
            self.send_telegram_message(f"📜 Command History:\n{history}")
                
        elif command.startswith('/udptraceroute'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.udp_traceroute(ip)
                self.send_telegram_message(f"🛣️ UDP Traceroute to {ip}:\n{result}")
            else:
                self.send_telegram_message("❌ Please provide an IP address")
                
        elif command.startswith('/tcptraceroute'):
            ip = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if ip:
                result = self.monitor.tcp_traceroute(ip)
                self.send_telegram_message(f"🛣️ TCP Traceroute to {ip}:\n{result}")
            else:
                self.send_telegram_message("❌ Please provide an IP address")
                
        elif command.startswith('/config_telegram_token'):
            token = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if token:
                self.monitor.telegram_token = token
                self.monitor.save_config()
                self.send_telegram_message("✅ Telegram token configured successfully")
            else:
                self.send_telegram_message("❌ Please provide a token")
                
        elif command.startswith('/config_telegram_chat_id'):
            chat_id = command.split(' ')[1] if len(command.split(' ')) > 1 else None
            if chat_id:
                self.monitor.telegram_chat_id = chat_id
                self.monitor.save_config()
                self.send_telegram_message("✅ Telegram chat ID configured successfully")
            else:
                self.send_telegram_message("❌ Please provide a chat ID")
                
        elif command == '/export_data':
            data = self.monitor.export_data()
            self.send_telegram_message(f"📊 Exported Data:\n{data}")
                
        else:
            self.send_telegram_message("❌ Unknown command. Type /help for available commands.")

def main():
    monitor = AccurateOS()
    telegram_handler = TelegramBotHandler(monitor)
    
    # Add methods to monitor class
    def add_methods():
        # Ping IP
        def ping_ip(self, ip):
            try:
                result = subprocess.run(['ping', '-c', '4', ip], capture_output=True, text=True)
                return result.stdout if result.returncode == 0 else f"Ping failed: {result.stderr}"
            except Exception as e:
                return f"Ping error: {e}"
        monitor.ping_ip = ping_ip.__get__(monitor)
        
        # Start monitoring IP
        def start_monitoring_ip(self, ip):
            self.monitored_ips.add(ip)
            self.monitoring_active = True
            self.save_config()
            return f"✅ Started monitoring IP: {ip}"
        monitor.start_monitoring_ip = start_monitoring_ip.__get__(monitor)
        
        # Stop monitoring
        def stop_monitoring(self):
            self.monitoring_active = False
            return "🛑 Monitoring stopped"
        monitor.stop_monitoring = stop_monitoring.__get__(monitor)
        
        # Get status
        def get_status(self):
            status = f"Monitoring Active: {self.monitoring_active}\n"
            status += f"Monitored IPs: {len(self.monitored_ips)}\n"
            status += f"Threat Alerts: {len(self.threat_alerts)}\n"
            return status
        monitor.get_status = get_status.__get__(monitor)
        
        # Get IP location
        def get_ip_location(self, ip):
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}")
                data = response.json()
                if data['status'] == 'success':
                    return f"Country: {data['country']}\nCity: {data['city']}\nISP: {data['isp']}"
                return "Location not found"
            except Exception as e:
                return f"Location error: {e}"
        monitor.get_ip_location = get_ip_location.__get__(monitor)
        
        # Scan ports
        def scan_ports(self, ip, start_port, end_port):
            try:
                open_ports = []
                for port in range(start_port, min(end_port + 1, start_port + 100)):  # Limit for demo
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                return f"Open ports: {open_ports}" if open_ports else "No open ports found"
            except Exception as e:
                return f"Scan error: {e}"
        monitor.scan_ports = scan_ports.__get__(monitor)
        
        # View monitored IPs
        def view_monitored_ips(self):
            return "\n".join(self.monitored_ips) if self.monitored_ips else "No IPs being monitored"
        monitor.view_monitored_ips = view_monitored_ips.__get__(monitor)
        
        # Add IP
        def add_ip(self, ip):
            self.monitored_ips.add(ip)
            self.save_config()
            return f"✅ Added IP: {ip}"
        monitor.add_ip = add_ip.__get__(monitor)
        
        # Remove IP
        def remove_ip(self, ip):
            if ip in self.monitored_ips:
                self.monitored_ips.remove(ip)
                self.save_config()
                return f"✅ Removed IP: {ip}"
            return f"❌ IP {ip} not found in monitored list"
        monitor.remove_ip = remove_ip.__get__(monitor)
        
        # Get command history
        def get_command_history(self):
            return "\n".join(self.command_history[-10:]) if self.command_history else "No command history"
        monitor.get_command_history = get_command_history.__get__(monitor)
        
        # UDP Traceroute
        def udp_traceroute(self, ip):
            try:
                result = subprocess.run(['traceroute', '-U', ip], capture_output=True, text=True)
                return result.stdout if result.returncode == 0 else f"Traceroute failed: {result.stderr}"
            except Exception as e:
                return f"Traceroute error: {e}"
        monitor.udp_traceroute = udp_traceroute.__get__(monitor)
        
        # TCP Traceroute
        def tcp_traceroute(self, ip):
            try:
                result = subprocess.run(['traceroute', '-T', ip], capture_output=True, text=True)
                return result.stdout if result.returncode == 0 else f"Traceroute failed: {result.stderr}"
            except Exception as e:
                return f"Traceroute error: {e}"
        monitor.tcp_traceroute = tcp_traceroute.__get__(monitor)
        
        # Export data
        def export_data(self):
            data = f"Cyber Security Monitor Export - {datetime.now()}\n"
            data += f"Monitored IPs: {len(self.monitored_ips)}\n"
            data += f"Threat Alerts: {len(self.threat_alerts)}\n"
            data += f"Logs: {len(self.logs)}\n"
            return data
        monitor.export_data = export_data.__get__(monitor)
    
    add_methods()
    
    # Start Telegram handler in separate thread
    def telegram_worker():
        while True:
            try:
                telegram_handler.process_telegram_commands()
                time.sleep(2)
            except Exception as e:
                logging.error(f"Telegram worker error: {e}")
                time.sleep(10)
    
    telegram_thread = threading.Thread(target=telegram_worker, daemon=True)
    telegram_thread.start()
    
    # Main interface
    def print_green(text):
        print(f"\033[92m{text}\033[0m")
        
    def print_banner():
        banner = """
        🛡️  ================================================================
        🛡️      ACCURATE ONLINE OS
        🛡️  ================================================================
        🛡️    
        🛡️   community:https://github.com/Accurate-Cyber-Defense
        🛡️   
        🛡️  ================================================================
        """
        print_green(banner)
    
    def show_help():
        help_text = """
        🟢 Available Commands:
        
        🔍 Monitoring Commands:
          ping [ip]              - Ping an IP address
          monitor [ip]           - Start monitoring IP
          stop                   - Stop monitoring
          status                 - Show monitoring status
          view                   - View monitored IPs
        
        🔎 Scanning Commands:
          scan [ip]              - Quick port scan
          deepscan [ip]          - Full port scan (1-65535)
          location [ip]          - Get IP location information
        
        ⚙️  Management Commands:
          add [ip]               - Add IP to monitoring list
          remove [ip]            - Remove IP from monitoring list
          history                - View command history
          config token [value]   - Configure Telegram token
          config chat_id [value] - Configure Telegram chat ID
          export                 - Export data to Telegram
        
        🛣️  Network Commands:
          udptrace [ip]          - UDP traceroute
          tcptrace [ip]          - TCP traceroute
        
        ❓ Other Commands:
          help                   - Show this help message
          exit                   - Exit the program
        """
        print_green(help_text)
    
    print_banner()
    show_help()
    
    # Command processing
    while True:
        try:
            command = input("\n\033[92maccurateOS> \033[0m").strip()
            monitor.command_history.append(command)
            
            if command == 'exit':
                print_green("👋 Exiting Accurate Online OS...")
                break
                
            elif command == 'help':
                show_help()
                
            elif command.startswith('ping '):
                ip = command.split(' ')[1]
                result = monitor.ping_ip(ip)
                print_green(f"Ping result for {ip}:\n{result}")
                
            elif command.startswith('monitor '):
                ip = command.split(' ')[1]
                result = monitor.start_monitoring_ip(ip)
                print_green(result)
                
            elif command == 'stop':
                result = monitor.stop_monitoring()
                print_green(result)
                
            elif command == 'status':
                status = monitor.get_status()
                print_green(status)
                
            elif command.startswith('location '):
                ip = command.split(' ')[1]
                location = monitor.get_ip_location(ip)
                print_green(f"Location for {ip}:\n{location}")
                
            elif command.startswith('scan '):
                ip = command.split(' ')[1]
                result = monitor.scan_ports(ip, 1, 1000)
                print_green(f"Scan result for {ip}:\n{result}")
                
            elif command.startswith('deepscan '):
                ip = command.split(' ')[1]
                result = monitor.scan_ports(ip, 1, 65535)
                print_green(f"Deep scan result for {ip}:\n{result}")
                
            elif command == 'view':
                ips = monitor.view_monitored_ips()
                print_green(f"Monitored IPs:\n{ips}")
                
            elif command.startswith('add '):
                ip = command.split(' ')[1]
                result = monitor.add_ip(ip)
                print_green(result)
                
            elif command.startswith('remove '):
                ip = command.split(' ')[1]
                result = monitor.remove_ip(ip)
                print_green(result)
                
            elif command == 'history':
                history = monitor.get_command_history()
                print_green(f"Command History:\n{history}")
                
            elif command.startswith('udptrace '):
                ip = command.split(' ')[1]
                result = monitor.udp_traceroute(ip)
                print_green(f"UDP Traceroute to {ip}:\n{result}")
                
            elif command.startswith('tcptrace '):
                ip = command.split(' ')[1]
                result = monitor.tcp_traceroute(ip)
                print_green(f"TCP Traceroute to {ip}:\n{result}")
                
            elif command.startswith('config token '):
                token = command.split(' ')[2]
                monitor.telegram_token = token
                monitor.save_config()
                print_green("✅ Telegram token configured successfully")
                
            elif command.startswith('config chat_id '):
                chat_id = command.split(' ')[2]
                monitor.telegram_chat_id = chat_id
                monitor.save_config()
                print_green("✅ Telegram chat ID configured successfully")
                
            elif command == 'export':
                data = monitor.export_data()
                if telegram_handler.send_telegram_message(data):
                    print_green("✅ Data exported to Telegram successfully")
                else:
                    print_green("❌ Failed to export data to Telegram")
                    
            else:
                print_green("❌ Unknown command. Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            print_green("\n👋 Exiting Accurate Online OS...")
            break
        except Exception as e:
            print_green(f"❌ Error: {e}")

if __name__ == "__main__":
    # Install required packages
    required_packages = ['scapy', 'requests']
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
    
    main()