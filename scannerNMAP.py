import asyncio
import argparse
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Any

class NetworkScanner:
    def __init__(self, targets: str, ports: str, nse_scripts: str = None):
        self.targets = targets
        self.ports = ports
        self.nse_scripts = nse_scripts
        self.results = []

    async def run_nmap(self) -> str:
        args = [ "-n", "-T4", "-sV", "--version-light", "-O", "-p", self.ports, "-oX", "-", "--open", self.targets]
        
        if self.nse_scripts:
            # Вставляем скрипты перед целью (хороший тон)
            args.insert(-1, "--script")
            args.insert(-1, self.nse_scripts)

        print(f"[*] Starting scan: nmap {' '.join(args)}")
        
        process = await asyncio.create_subprocess_exec(
            'nmap', *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_msg = stderr.decode().strip()
            if "requires root privileges" in error_msg:
                raise PermissionError("Для определения ОС (-O) требуются права sudo.")
            raise Exception(f"Nmap error: {error_msg}")

        return stdout.decode()

    def parse_xml(self, xml_data: str) -> List[Dict[str, Any]]:
        """Парсинг XML 'на лету' и извлечение ключевых метрик."""
        root = ET.fromstring(xml_data)
        scan_results = []

        for host in root.findall('host'):
            addr = host.find('address').get('addr') if host.find('address') is not None else "Unknown"
            status = host.find('status').get('state')
            
            host_info = {
                "ip": addr,
                "status": status,
                "os": "Unknown",
                "ports": []
            }
            os_match = host.find('os/osmatch') # Определение ОС
            if os_match is not None:
                host_info["os"] = os_match.get('name')

            for port in host.findall('.//port'):  # Сбор портов
                portid = port.get('portid')
                state = port.find('state').get('state')
                service = port.find('service')          
                service_info = {
                    "port": portid, "state": state, "name": service.get('name') if service is not None else "unknown",
                    "product": service.get('product', 'N/A'), "version": service.get('version', 'N/A'),
                    "extrainfo": service.get('extrainfo', 'N/A')
                }
                host_info["ports"].append(service_info)
            scan_results.append(host_info)      
        return scan_results

    async def execute(self):
        try:
            raw_xml = await self.run_nmap()
            self.results = self.parse_xml(raw_xml)
            return self.results
        except Exception as e:
            print(f"[!] Critical Error: {e}")
            return None
def save_report(data: List[Dict], format: str):
    filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if format == 'json':
        with open(f"{filename}.json", 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[+] JSON report saved to {filename}.json")
    else:
        with open(f"{filename}.md", 'w') as f:
            f.write(f"# Network Scan Report - {datetime.now()}\n\n")
            for host in data:
                f.write(f"### Host: {host['ip']} ({host['os']})\n")
                f.write("| Port | Service | Version |\n|---|---|---|\n")
                for p in host['ports']:
                    f.write(f"| {p['port']} | {p['name']} | {p['product']} {p['version']} |\n")
                f.write("\n")
        print(f"[+] Markdown report saved to {filename}.md")

async def main():
    parser = argparse.ArgumentParser(description="Async DevSecOps Nmap Scanner")
    parser.add_argument("targets", help="IP range or subnet (e.g., 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="22,80,443,445,8080", help="Comma separated ports")
    parser.add_argument("--scripts", help="Nmap scripts (NSE) to run")
    parser.add_argument("--format", choices=['json', 'md'], default='json', help="Output format")
    
    args = parser.parse_args()

    scanner = NetworkScanner(args.targets, args.ports, args.scripts)
    results = await scanner.execute()

    if results:
        save_report(results, args.format)

if __name__ == "__main__":
    asyncio.run(main())
