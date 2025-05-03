# firewall_rule.py
from ipaddress import ip_network
from scapy.all import TCP, UDP, ICMP, IP

class FirewallRule:
    def __init__(self, rule_id, name, action, protocol=None, src_ip=None, dst_ip=None, src_port=None, dst_port=None, description=""):
        self.rule_id = rule_id
        self.name = name
        self.action = action
        self.protocol = protocol
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.description = description

    def matches(self, packet):
        if self.protocol and not self._check_protocol(packet):
            return False
        if not self._check_ips(packet):
            return False
        if not self._check_ports(packet):
            return False
        return True

    def _check_protocol(self, packet):
        if self.protocol.lower() == 'tcp' and not packet.haslayer(TCP):
            return False
        if self.protocol.lower() == 'udp' and not packet.haslayer(UDP):
            return False
        if self.protocol.lower() == 'icmp' and not packet.haslayer(ICMP):
            return False
        return True

    def _check_ips(self, packet):
        if not packet.haslayer(IP):
            return False
        if self.src_ip and packet[IP].src not in self._parse_ip_range(self.src_ip):
            return False
        if self.dst_ip and packet[IP].dst not in self._parse_ip_range(self.dst_ip):
            return False
        return True

    def _check_ports(self, packet):
        if self.src_port and not self._check_port(packet, 'sport', self.src_port):
            return False
        if self.dst_port and not self._check_port(packet, 'dport', self.dst_port):
            return False
        return True

    def _check_port(self, packet, port_type, port_rule):
        port_values = self._parse_port_range(port_rule)
        if port_type == 'sport':
            if packet.haslayer(TCP) and packet[TCP].sport in port_values:
                return True
            if packet.haslayer(UDP) and packet[UDP].sport in port_values:
                return True
        elif port_type == 'dport':
            if packet.haslayer(TCP) and packet[TCP].dport in port_values:
                return True
            if packet.haslayer(UDP) and packet[UDP].dport in port_values:
                return True
        return False

    def _parse_ip_range(self, ip_rule):
        try:
            if "/" in ip_rule:
                return [str(ip) for ip in ip_network(ip_rule)]
            else:
                return [ip_rule]
        except ValueError:
            return []

    def _parse_port_range(self, port_rule):
        if isinstance(port_rule, int):
            return [port_rule]
        if isinstance(port_rule, str):
            if "-" in port_rule:
                start, end = map(int, port_rule.split("-"))
                return list(range(start, end + 1))
            else:
                return [int(port_rule)]
        return []

    def __repr__(self):
        return f"<FirewallRule {self.rule_id}: {self.name} - {self.action}>"


# firewall_rule_manager.py
import json
from firewall import FirewallRule

class FirewallRuleManager:
    def __init__(self, rules_file='rules.json'):
        self.rules = []
        self.rules_file = rules_file

    def load_rules(self):
        try:
            with open(self.rules_file) as f:
                rules_data = json.load(f)
                self.rules = [FirewallRule(**rule) for rule in rules_data]
        except (FileNotFoundError, json.JSONDecodeError):
            self.rules = []

    def save_rules(self):
        rules_data = [rule.__dict__ for rule in self.rules]
        with open(self.rules_file, 'w') as f:
            json.dump(rules_data, f, indent=2)

    def add_rule(self, rule):
        self.rules.append(rule)
        self.save_rules()

    def remove_rule(self, rule_id):
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        self.save_rules()


# packet_sniffer.py
from scapy.all import sniff

class PacketSniffer:
    def __init__(self, interface=None):
        self.interface = interface
        self.running = False

    def start_sniffing(self, packet_handler):
        try:
            self.running = True
            sniff(iface=self.interface, prn=packet_handler, store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            print(f"[ERREUR] Échec du sniffing : {e}")

    def stop_sniffing(self):
        self.running = False


# packet_filter.py
class PacketFilter:
    def __init__(self, rule_manager):
        self.rule_manager = rule_manager

    def filter_packet(self, packet):
        for rule in self.rule_manager.rules:
            if rule.matches(packet):
                return rule.action, rule
        return 'allow', None


# packet_blocker.py
try:
    import pydivert
except ImportError:
    pydivert = None

class PacketBlocker:
    def __init__(self):
        self.win_divert = None

    def start_blocking(self):
        if pydivert:
            self.win_divert = pydivert.WinDivert()
            self.win_divert.open()

    def stop_blocking(self):
        if self.win_divert:
            self.win_divert.close()

    def process_packet(self, packet, decision):
        if decision == 'deny':
            return
        if self.win_divert:
            self.win_divert.send(packet)


# firewall_logger.py
import json
import logging
from datetime import datetime
from scapy.all import IP, TCP, UDP

class FirewallLogger:
    def __init__(self, log_file='firewall.log'):
        self.log_file = log_file
        logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

    def log_event(self, packet, action, matched_rule=None):
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': action,
                'source_ip': packet[IP].src if IP in packet else None,
                'dest_ip': packet[IP].dst if IP in packet else None,
                'protocol': packet.payload.name if hasattr(packet, 'payload') else None,
                'source_port': packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None),
                'dest_port': packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None),
                'matched_rule': matched_rule.rule_id if matched_rule else None
            }
            logging.info(json.dumps(log_entry))
        except Exception as e:
            print(f"[ERREUR LOGGER] {e}")


# firewall.py
from firewall import FirewallRuleManager
from firewall import PacketSniffer
from firewall import PacketFilter
from firewall import FirewallLogger
from firewall import PacketBlocker

class Firewall:
    def __init__(self):
        self.rule_manager = FirewallRuleManager()
        self.sniffer = PacketSniffer()
        self.filter = PacketFilter(self.rule_manager)
        self.logger = FirewallLogger()
        self.blocker = PacketBlocker()

    def start(self):
        self.rule_manager.load_rules()
        try:
            self.sniffer.start_sniffing(self.handle_packet)
        except KeyboardInterrupt:
            print("[INFO] Firewall arrêté par l'utilisateur.")
            self.sniffer.stop_sniffing()

    def handle_packet(self, packet):
        action, rule = self.filter.filter_packet(packet)
        self.logger.log_event(packet, action, rule)
        self.blocker.process_packet(packet, action)  # Uncomment if using pydivert
