class AP_fingerprint_t:
    def __init__(self):
        self.rssi: int = 0
        self.ssid: str = ""
        self.mac: bytes = b'' # 6 bytes
        self.bssid: bytes = b'' # 6 bytes
        self.channel: int = 0
        self.data_channel: int = 0
        self.capability_info: int = 0 # 2 bytes
        self.encryption: int = 0 # 1 byte
        self.linked_sta_macs: list[bytes] = [] # List of 6-byte MACs

    def __repr__(self):
        return (f"AP(MAC={self.mac.hex().upper()}, SSID='{self.ssid}', RSSI={self.rssi}, "
                f"Channel={self.channel}, DataChannel={self.data_channel}, "
                f"CapInfo={self.capability_info}, Enc={self.encryption}, "
                f"Linked STAs Count={len(self.linked_sta_macs)})")
    
class STA_fingerprint_t:
    def __init__(self):
        self.rssi: int = 0
        self.mac: bytes = b'' # 6 bytes
        self.broadcast: bool = False
        self.ssid_ap: str = ""
        self.channel: int = 0
        self.data_channel: int = 0
        self.linked_ap_macs: list[bytes] = []
    
    def __repr__(self):
        return (f"STA(MAC={self.mac.hex().upper()}, SSID_AP='{self.ssid_ap}', RSSI={self.rssi}, "
                f"Channel={self.channel}, DataChannel={self.data_channel}, "
                f"Broadcast={self.broadcast}, Linked APs Count={len(self.linked_ap_macs)})")

def print_device_fingerprints(ap_list: list[AP_fingerprint_t], sta_list: list[STA_fingerprint_t]):
    """Print all the sniffed data and infos with improved formatting."""

    def format_mac(mac_bytes: bytearray) -> str:
        """Formats a bytearray MAC address to XX:XX:XX:XX:XX:XX string."""
        return ':'.join(f'{b:02X}' for b in mac_bytes)

    print("\n" + "=" * 50)
    print("           --- WI-FI FINGERPRINTS ---")
    print("=" * 50)

    # 1. Create maps for AP and STA lookup by MAC for links
    mac_to_ap_map = {ap.mac: ap for ap in ap_list}
    mac_to_sta_map = {sta.mac: sta for sta in sta_list}

    # 2. Print AP information
    print("\n--- Access Points (APs) ---")
    if not ap_list:
        print("    No APs detected.")
    else:
        for i, ap in enumerate(ap_list):
            print(f"\nAP #{i+1}:")
            print(f"  {'MAC Address:'.ljust(18)} {format_mac(ap.mac)}")
            print(f"  {'SSID:'.ljust(18)} '{ap.ssid.decode(errors='ignore')}' (Length: {len(ap.ssid)})")
            print(f"  {'BSSID:'.ljust(18)} {format_mac(ap.bssid)}")
            print(f"  {'RSSI:'.ljust(18)} {ap.rssi} dBm")
            print(f"  {'Channel:'.ljust(18)} {ap.channel}")
            print(f"  {'Data Channel:'.ljust(18)} {ap.data_channel}")
            print(f"  {'Capability Info:'.ljust(18)} {ap.capability_info} (0x{ap.capability_info:04X})")
            print(f"  {'Encryption:'.ljust(18)} {ap.encryption}")

            print(f"  {'Linked Clients:'.ljust(18)} ({len(ap.linked_sta_macs)} found)")
            if not ap.linked_sta_macs:
                print("    No client stations linked to this AP.")
            else:
                for j, sta_mac in enumerate(ap.linked_sta_macs):
                    linked_sta_obj = mac_to_sta_map.get(sta_mac)
                    if linked_sta_obj:
                        print(f"    - #{j+1}: {format_mac(sta_mac)} (Linked to STA SSID: '{linked_sta_obj.ssid_ap.decode(errors='ignore')}')")
                    else:
                        print(f"    - #{j+1}: {format_mac(sta_mac)} (Client STA not found in global list)")

    # 3. Print STA information
    print("\n--- Client Stations (STAs) ---")
    if not sta_list:
        print("    No STAs detected.")
    else:
        for i, sta in enumerate(sta_list):
            print(f"\nSTA #{i+1}:")
            print(f"  {'MAC Address:'.ljust(18)} {format_mac(sta.mac)}")
            print(f"  {'RSSI:'.ljust(18)} {sta.rssi} dBm")
            print(f"  {'Broadcast:'.ljust(18)} {'Yes' if sta.broadcast else 'No'}")
            print(f"  {'Probed AP SSID:'.ljust(18)} '{sta.ssid_ap.decode(errors='ignore')}' (Length: {len(sta.ssid_ap)})")
            print(f"  {'Channel:'.ljust(18)} {sta.channel}")
            print(f"  {'Data Channel:'.ljust(18)} {sta.data_channel}")

            print(f"  {'Linked APs:'.ljust(18)} ({len(sta.linked_ap_macs)} found)")
            if not sta.linked_ap_macs:
                print("    No access points linked to this STA.")
            else:
                for j, ap_mac in enumerate(sta.linked_ap_macs):
                    linked_ap_obj = mac_to_ap_map.get(ap_mac)
                    if linked_ap_obj:
                        print(f"    - #{j+1}: {format_mac(ap_mac)} (Linked to AP SSID: '{linked_ap_obj.ssid.decode(errors='ignore')}')")
                    else:
                        print(f"    - #{j+1}: {format_mac(ap_mac)} (Access Point not found in global list)")

    print("\n" + "=" * 50)
    print("             --- END OF REPORT ---")
    print("=" * 50)