from firewall import FirewallRuleManager
from firewall import PacketSniffer
from firewall import PacketFilter
from firewall import FirewallLogger
from firewall import PacketBlocker  # Pour Windows
from firewall import FirewallRule
from scapy.all import *
import threading

class Firewall:
    def __init__(self):
        self.rule_manager = FirewallRuleManager()
        self.rule_manager.load_rules()
        self.logger = FirewallLogger()
        self.filter = PacketFilter(self.rule_manager)
        self.sniffer = PacketSniffer()
        self.blocker = PacketBlocker()  # optionnel selon OS

    def handle_packet(self, packet):
        action = self.filter.filter_packet(packet)
        matched_rule = None
        for rule in self.rule_manager.rules:
            if rule.matches(packet):
                matched_rule = rule
                break
        self.logger.log_event(packet, action, matched_rule)
        if action == "deny":
            print(f"[BLOCKED] {packet.summary()}")
        else:
            print(f"[ALLOWED] {packet.summary()}")

    def start(self):
        print("[*] Firewall en cours d'exécution...")
        self.sniffer.start_sniffing(self.handle_packet)

if __name__ == "__main__":
    firewall = Firewall()
    firewall.start()