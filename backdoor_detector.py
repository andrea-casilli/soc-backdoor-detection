#!/usr/bin/env python3
"""
SOC Backdoor Detection Tool
Script to detect potential backdoors on Linux/Unix systems
"""

import os
import sys
import pwd
import grp
import socket
import subprocess
import hashlib
import json
from datetime import datetime
from pathlib import Path

class BackdoorDetector:
    def __init__(self):
        self.suspicious_items = []
        self.report = {
            'timestamp': datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'detections': []
        }
        
        # Sensitive directories to monitor
        self.sensitive_directories = [
            '/tmp',
            '/dev/shm',
            '/var/tmp',
            '/var/www/html',
            '/usr/local/bin',
            '/usr/bin',
            '/bin',
            '/sbin',
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.weekly',
            '/etc/cron.monthly',
            '/etc/systemd/system'
        ]
        
        # Suspicious extensions
        self.suspicious_extensions = ['.sh', '.py', '.pl', '.rb', '.php', '.exe', '.bin']
        
        # Common critical processes
        self.common_processes = ['sshd', 'httpd', 'apache2', 'nginx', 'mysql', 'postgresql']
        
        # Known backdoor hashes
        self.known_backdoors = self.load_known_backdoors()

    def load_known_backdoors(self):
        """Load known backdoor hashes from external file"""
        # In a production environment, load from database or config file
        return {
            'c99shell.php': '3b2a5b7b8b9c8d9e0f1a2b3c4d5e6f7g8h9i0j1k',
            'wso.php': '1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t',
            'r57shell.php': '9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2i1h0g'
        }

    def check_suspicious_files(self):
        """Search for files with anomalous permissions or in suspicious directories"""
        print("[*] Checking suspicious files...")
        
        for directory in self.sensitive_directories:
            if os.path.exists(directory):
                try:
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            full_path = os.path.join(root, file)
                            
                            # Check suspicious extensions
                            if any(file.endswith(ext) for ext in self.suspicious_extensions):
                                self.analyze_file(full_path)
                                
                except PermissionError:
                    continue

    def analyze_file(self, filepath):
        """Analyze specific file for suspicious characteristics"""
        try:
            stat = os.stat(filepath)
            
            # Check setuid/setgid permissions
            if stat.st_mode & 0o4000 or stat.st_mode & 0o2000:
                self.add_detection({
                    'type': 'setuid_setgid',
                    'path': filepath,
                    'description': 'File with setuid/setgid permissions',
                    'permissions': oct(stat.st_mode)[-3:]
                })
            
            # Check if executable and owned by root
            if stat.st_mode & 0o111 and stat.st_uid == 0:
                if self.is_suspicious_process(filepath):
                    self.add_detection({
                        'type': 'root_executable',
                        'path': filepath,
                        'description': 'Uncommon root executable',
                        'owner': 'root'
                    })
            
            # Calculate hash for comparison with known backdoors
            if filepath.endswith('.php') or filepath.endswith('.py'):
                file_hash = self.calculate_hash(filepath)
                if file_hash in self.known_backdoors.values():
                    self.add_detection({
                        'type': 'known_backdoor',
                        'path': filepath,
                        'description': 'Hash matches known backdoor',
                        'hash': file_hash
                    })
                    
        except (OSError, IOError):
            pass

    def is_suspicious_process(self, filepath):
        """Determine if an executable is potentially suspicious"""
        filename = os.path.basename(filepath)
        
        # Whitelist of normal processes
        normal_processes = ['bash', 'sh', 'python', 'perl', 'php', 'systemd', 'init']
        
        if filename in normal_processes:
            return False
            
        # Check if it's a common system command
        if os.path.exists(f'/usr/bin/{filename}') or os.path.exists(f'/bin/{filename}'):
            return False
            
        return True

    def calculate_hash(self, filepath):
        """Calculate SHA256 hash of a file"""
        try:
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return None

    def check_processes(self):
        """Check running processes"""
        print("[*] Checking running processes...")
        
        try:
            # Get process list
            ps_output = subprocess.check_output(['ps', 'aux'], universal_newlines=True)
            processes = ps_output.split('\n')[1:]  # Skip header
            
            for process in processes:
                if not process.strip():
                    continue
                    
                parts = process.split()
                if len(parts) < 11:
                    continue
                    
                user = parts[0]
                pid = parts[1]
                cmd = ' '.join(parts[10:])
                
                # Look for reverse shells
                if 'bash -i' in cmd or 'sh -i' in cmd:
                    if 'nc -' in cmd or 'netcat' in cmd or 'ncat' in cmd:
                        self.add_detection({
                            'type': 'reverse_shell',
                            'pid': pid,
                            'user': user,
                            'command': cmd,
                            'description': 'Possible reverse shell detected'
                        })
                
                # Look for suspicious network connections in processes
                if 'nc ' in cmd or 'netcat' in cmd:
                    self.add_detection({
                        'type': 'netcat_process',
                        'pid': pid,
                        'user': user,
                        'command': cmd,
                        'description': 'Netcat running (potential backdoor)'
                    })
                    
        except subprocess.CalledProcessError:
            pass

    def check_network_connections(self):
        """Check suspicious network connections"""
        print("[*] Checking network connections...")
        
        try:
            # Get active network connections
            netstat_output = subprocess.check_output(
                ['netstat', '-tunap'], 
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            )
            
            connections = netstat_output.split('\n')
            
            for conn in connections:
                if 'ESTABLISHED' in conn or 'LISTEN' in conn:
                    if '0.0.0.0:' in conn or ':::' in conn:
                        if 'sshd' not in conn and 'httpd' not in conn and 'apache' not in conn:
                            self.add_detection({
                                'type': 'anomalous_port',
                                'connection': conn.strip(),
                                'description': 'Non-standard listening port'
                            })
                            
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

    def check_cron_jobs(self):
        """Check suspicious cron jobs"""
        print("[*] Checking cron jobs...")
        
        cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/var/spool/cron/crontabs']
        
        for cron_dir in cron_dirs:
            if os.path.exists(cron_dir):
                try:
                    for file in os.listdir(cron_dir):
                        filepath = os.path.join(cron_dir, file)
                        if os.path.isfile(filepath):
                            with open(filepath, 'r') as f:
                                content = f.read()
                                if 'wget' in content or 'curl' in content or 'nc' in content:
                                    self.add_detection({
                                        'type': 'suspicious_cron',
                                        'path': filepath,
                                        'description': 'Cron job with downloads or network connections'
                                    })
                except (PermissionError, IOError):
                    continue

    def check_systemd_services(self):
        """Check suspicious systemd services"""
        print("[*] Checking systemd services...")
        
        try:
            systemd_output = subprocess.check_output(
                ['systemctl', 'list-units', '--type=service', '--all'],
                universal_newlines=True
            )
            
            if 'created by manual page' in systemd_output.lower():
                self.add_detection({
                    'type': 'suspicious_systemd',
                    'description': 'Possible malicious systemd service detected'
                })
                
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

    def add_detection(self, detection):
        """Add a detection to the report"""
        self.report['detections'].append(detection)
        print(f"[!] Detected: {detection['description']} - {detection.get('path', '')}")

    def generate_report(self):
        """Generate final report"""
        print("\n" + "="*60)
        print("BACKDOOR DETECTION REPORT")
        print("="*60)
        print(f"Timestamp: {self.report['timestamp']}")
        print(f"Hostname: {self.report['hostname']}")
        print(f"Total detections: {len(self.report['detections'])}")
        print("-"*60)
        
        if self.report['detections']:
            for i, detection in enumerate(self.report['detections'], 1):
                print(f"\n[{i}] {detection['type'].upper()}")
                print(f"    Description: {detection['description']}")
                if 'path' in detection:
                    print(f"    Path: {detection['path']}")
                if 'command' in detection:
                    print(f"    Command: {detection['command']}")
                if 'connection' in detection:
                    print(f"    Connection: {detection['connection']}")
        else:
            print("\n[OK] No backdoors detected")
            
        print("="*60)
        
        # Save report to file
        filename = f"backdoor_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.report, f, indent=2)
        print(f"\nReport saved to: {filename}")

    def run_scan(self):
        """Execute all checks"""
        print("="*60)
        print("BACKDOOR SCAN INITIALIZED")
        print("="*60)
        
        self.check_suspicious_files()
        self.check_processes()
        self.check_network_connections()
        self.check_cron_jobs()
        self.check_systemd_services()
        
        self.generate_report()

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] Warning: Some checks require root privileges")
        print("[!] Run with sudo for complete results")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    detector = BackdoorDetector()
    detector.run_scan()

if __name__ == "__main__":
    main()
