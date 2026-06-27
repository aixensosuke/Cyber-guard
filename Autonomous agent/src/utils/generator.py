import random
from datetime import datetime, timedelta
from typing import List, Dict, Any
from faker import Faker
from src.config import Config

fake = Faker()

class SecurityLogGenerator:
    def __init__(self, seed: int = 42):
        Faker.seed(seed)
        random.seed(seed)
        
        self.normal_users = ["jdoe", "asmith", "mross", "cgarcia", "lking"]
        self.normal_hosts = ["DC-01.bank.local", "DB-SRV.bank.local", "WKSTN-101", "WKSTN-102", "WKSTN-103"]
        self.normal_ips = [fake.ipv4_private() for _ in range(5)]
        
        # Threat actor characteristics
        self.attacker_ip = "192.168.99.180"
        self.victim_user = "admin"
        self.victim_host = "DB-SRV.bank.local"
        self.exfiltration_dest = "203.0.113.88" # Suspicious external IP

    def generate_baseline(self, num_events: int = 200) -> List[Dict[str, Any]]:
        events = []
        start_time = datetime.utcnow() - timedelta(days=1)
        
        for i in range(num_events):
            time_delta = timedelta(seconds=random.randint(10, 300))
            timestamp = (start_time + time_delta).isoformat() + "Z"
            start_time = start_time + time_delta

            log_type = random.choice(["windows", "ssh", "proxy"])
            
            if log_type == "windows":
                user = random.choice(self.normal_users)
                host = random.choice(self.normal_hosts)
                action = random.choice(["process_spawn", "file_modification", "login_attempt"])
                
                if action == "process_spawn":
                    proc = random.choice(["chrome.exe", "outlook.exe", "excel.exe", "explorer.exe", "git.exe"])
                    cmd = f"C:\\Program Files\\{proc.split('.')[0]}\\{proc} --args"
                    event = {
                        "timestamp": timestamp,
                        "log_source": "windows_event",
                        "severity": "INFO",
                        "username": user,
                        "source_ip": random.choice(self.normal_ips),
                        "action_type": "process_spawn",
                        "process_name": proc,
                        "command_line": cmd,
                        "status": "success"
                    }
                elif action == "file_modification":
                    file = random.choice(["document.docx", "spreadsheet.xlsx", "notes.txt", "code.py"])
                    event = {
                        "timestamp": timestamp,
                        "log_source": "windows_event",
                        "severity": "INFO",
                        "username": user,
                        "action_type": "file_modification",
                        "file_path": f"C:\\Users\\{user}\\Documents\\{file}",
                        "status": "success"
                    }
                else: # login
                    event = {
                        "timestamp": timestamp,
                        "log_source": "windows_event",
                        "severity": "INFO",
                        "username": user,
                        "source_ip": random.choice(self.normal_ips),
                        "action_type": "login_attempt",
                        "status": "success"
                    }
                    
            elif log_type == "ssh":
                user = random.choice(self.normal_users + ["root"])
                ip = random.choice(self.normal_ips)
                status = "success" if user != "root" else "failure"
                event = {
                    "timestamp": timestamp,
                    "log_source": "ssh",
                    "severity": "INFO" if status == "success" else "WARNING",
                    "username": user,
                    "source_ip": ip,
                    "destination_ip": "10.0.0.12",
                    "destination_port": 22,
                    "action_type": "login_attempt",
                    "status": status
                }
                
            else: # proxy (web traffic)
                user = random.choice(self.normal_users)
                ip = random.choice(self.normal_ips)
                dest = fake.ipv4_public()
                bytes_sent = float(random.randint(100, 15000))
                event = {
                    "timestamp": timestamp,
                    "log_source": "proxy",
                    "severity": "INFO",
                    "username": user,
                    "source_ip": ip,
                    "destination_ip": dest,
                    "destination_port": 443,
                    "action_type": "network_connect",
                    "bytes_transferred": bytes_sent,
                    "status": "success"
                }
            events.append(event)
            
        return events

    def generate_attack_sequence(self, start_time: datetime) -> List[Dict[str, Any]]:
        events = []
        current_time = start_time

        # Step 1: Recon / Port Scan (from Attacker IP targeting DB-SRV)
        # MITRE: Discovery (T1046 Network Service Scanning)
        for port in [21, 22, 80, 139, 443, 445, 1433, 3306, 3389, 8080]:
            current_time += timedelta(milliseconds=random.randint(50, 200))
            events.append({
                "timestamp": current_time.isoformat() + "Z",
                "log_source": "firewall",
                "severity": "WARNING",
                "source_ip": self.attacker_ip,
                "destination_ip": "10.0.0.15", # DB-SRV internal IP
                "destination_port": port,
                "action_type": "network_connect",
                "status": "failure", # blocked/rejected
                "bytes_transferred": 0.0
            })

        # Step 2: SSH Brute Force on DB-SRV
        # MITRE: Credential Access (T1110 Brute Force)
        for _ in range(8):
            current_time += timedelta(seconds=random.randint(2, 10))
            events.append({
                "timestamp": current_time.isoformat() + "Z",
                "log_source": "ssh",
                "severity": "WARNING",
                "username": self.victim_user,
                "source_ip": self.attacker_ip,
                "destination_ip": "10.0.0.15",
                "destination_port": 22,
                "action_type": "login_attempt",
                "status": "failure"
            })

        # Successful Login (Brute force success)
        # MITRE: Initial Access / Lateral Movement
        current_time += timedelta(seconds=5)
        events.append({
            "timestamp": current_time.isoformat() + "Z",
            "log_source": "ssh",
            "severity": "CRITICAL",
            "username": self.victim_user,
            "source_ip": self.attacker_ip,
            "destination_ip": "10.0.0.15",
            "destination_port": 22,
            "action_type": "login_attempt",
            "status": "success"
        })

        # Step 3: Privilege Escalation & Execution (compromised admin running unusual actions)
        # MITRE: Execution, Privilege Escalation
        bad_commands = [
            ("whoami", "whoami"),
            ("net user", "net user /domain"),
            ("mimikatz.exe", "C:\\temp\\mimikatz.exe sekurlsa::logonpasswords"),
            ("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet")
        ]
        
        for proc, cmd in bad_commands:
            current_time += timedelta(minutes=random.randint(1, 3))
            events.append({
                "timestamp": current_time.isoformat() + "Z",
                "log_source": "windows_event",
                "severity": "CRITICAL",
                "username": self.victim_user,
                "source_ip": self.attacker_ip,
                "action_type": "process_spawn",
                "process_name": proc,
                "command_line": cmd,
                "status": "success"
            })

        # Step 4: Exfiltration (massive bytes transferred to a suspicious external IP)
        # MITRE: Exfiltration (T1048 Exfiltration Over Alternative Protocol)
        current_time += timedelta(minutes=2)
        events.append({
            "timestamp": current_time.isoformat() + "Z",
            "log_source": "proxy",
            "severity": "CRITICAL",
            "username": self.victim_user,
            "source_ip": "10.0.0.15", # Database server sending data
            "destination_ip": self.exfiltration_dest,
            "destination_port": 443,
            "action_type": "network_connect",
            "bytes_transferred": 524288000.0, # 500 MB
            "status": "success"
        })

        return events
