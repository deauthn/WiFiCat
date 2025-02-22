import re

from scapy.config import conf
from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    RadioTap,
)
from scapy.layers.eap import EAPOL
from scapy.sendrecv import sniff

from utils import org


class Shifter:
    BLACKLIST = "ffffffffffff"

    def __init__(
        self, iface, bss, ess, verbose
    ):
        self.iface = iface
        conf.iface = self.iface
        self.bss = bss
        self.ess = ess
        self.verbose = verbose
        self.bss_counter = set()
        self.clients = []
        self.cells = []
        self.ALSA_clients = {}

    def check_cipher(
        self, layer, cipher_type
    ):
        """
        Check the cipher based on the cipher type.

        :param layer: The layer containing cipher information.
        :param cipher_type: Type of the cipher ('48' or '221').
        :return: A list containing the user cipher and PSK.
        """
        compound = layer.info
        sections = compound.split(
            "\x00\x00"
        )[1:]
        u_cipher = ""
        p_cipher = ""
        psk = ""

        u_ciphers_48 = {
            "\x0f\xac\x00": "GROUP",
            "\x0f\xac\x01": "WEP",
            "\x0f\xac\x02": "TKIP",
            "\x0f\xac\x04": "CCMP",
            "\x0f\xac\x05": "WEP",
        }

        p_ciphers_48 = {
            "\x0f\xac\x00": "GROUP",
            "\x0f\xac\x01": "WEP",
            "\x0f\xac\x02\x00\x0f\xac\x04": "TKIP/CCMP",
            "\x0f\xac\x04\x00\x0f\xac\x02": "CCMP/TKIP",
            "\x0f\xac\x02": "TKIP",
            "\x0f\xac\x04": "CCMP",
            "\x0f\xac\x05": "WEP",
        }

        u_ciphers_221 = {
            "P\xf2\x00": "GROUP",
            "P\xf2\x01": "WEP",
            "P\xf2\x02": "TKIP",
            "P\xf2\x04": "CCMP",
            "P\xf2\x05": "WEP",
        }

        p_ciphers_221 = {
            "P\xf2\x00": "GROUP",
            "P\xf2\x01": "WEP",
            "P\xf2\x02\x00P\xf2\x04": "TKIP/CCMP",
            "P\xf2\x04\x00P\xf2\x02": "CCMP/TKIP",
            "P\xf2\x02": "TKIP",
            "P\xf2\x04": "CCMP",
            "P\xf2\x05": "WEP",
        }

        psk_keys = {
            "\x0f\xac\x01": "MGT",
            "\x0f\xac\x02": "PSK",
            "P\xf2\x01": "MGT",
            "P\xf2\x02": "PSK",
        }

        cipher_map = (
            u_ciphers_48
            if cipher_type == 48
            else u_ciphers_221
        )
        p_cipher_map = (
            p_ciphers_48
            if cipher_type == 48
            else p_ciphers_221
        )

        for key, value in cipher_map.items():
            if sections and sections[
                0
            ].startswith(key):
                u_cipher = value
        for (
            key,
            value,
        ) in p_cipher_map.items():
            if len(
                sections
            ) > 1 and sections[1].startswith(
                key
            ):
                p_cipher = value
        for key, value in psk_keys.items():
            if len(
                sections
            ) > 2 and sections[2].startswith(
                key
            ):
                psk = value

        return [u_cipher, psk]

    def enc_shift(self, cap, ELTLAYERS):
        """
        Process encryption information from the captured packet.

        :param cap: Captured packet capabilities.
        :param ELTLAYERS: Elements of the captured layers.
        :return: Layer data containing ESSID, channel, auth, cipher, and PSK.
        """
        layer_data = {
            "essid": "",
            "channel": 0,
            "auth": "",
            "cipher": "",
            "psk": "",
        }
        for dig in range(20):
            try:
                if ELTLAYERS[dig].ID == 0:
                    layer_data["essid"] = (
                        ELTLAYERS[dig].info
                    )
                elif (
                    ELTLAYERS[dig].ID == 3
                    and ELTLAYERS[dig].len
                    == 1
                ):
                    layer_data["channel"] = (
                        ord(
                            ELTLAYERS[
                                dig
                            ].info
                        )
                    )
                elif ELTLAYERS[dig].ID == 48:
                    layer_data["auth"] = (
                        "WPA2"
                    )
                    cipher, psk = (
                        self.check_cipher(
                            ELTLAYERS[dig],
                            48,
                        )
                    )
                    (
                        layer_data["cipher"],
                        layer_data["psk"],
                    ) = cipher, psk
                elif ELTLAYERS[
                    dig
                ].ID == 221 and ELTLAYERS[
                    dig
                ].info.startswith(
                    "\x00P\xf2\x01\x01\x00"
                ):
                    layer_data["auth"] = (
                        "WPA"
                        + (
                            "/WPA"
                            if layer_data[
                                "auth"
                            ]
                            else ""
                        )
                    )
                    cipher, psk = (
                        self.check_cipher(
                            ELTLAYERS[dig],
                            221,
                        )
                    )
                    (
                        layer_data["cipher"],
                        layer_data["psk"],
                    ) = cipher, psk
            except IndexError:
                break

        if not layer_data["auth"]:
            layer_data["auth"] = (
                "WEP"
                if "privacy" in cap
                else "OPEN"
            )

        return layer_data

    def dBM_sig(self, pkt):
        """
        Extract the dBm signal strength from the packet.

        :param pkt: Packet to extract signal from.
        :return: Signal strength in dBm.
        """
        if pkt.haslayer(RadioTap):
            extra = pkt.notdecoded
            for p in extra:
                dbm_sig = -(256 - ord(p))
                if -90 < dbm_sig < -20:
                    return dbm_sig
        return "?"

    def filtertify(self, bssid, data):
        """
        Check if the given BSSID and ESSID match the filter criteria.

        :param bssid: The BSSID being checked.
        :param data: Data containing ESSID.
        :return: Boolean indicating if the filter matches.
        """
        return (
            self.bss is not None
            and self.bss != bssid
        ) or (
            self.ess is not None
            and self.ess != data["essid"]
        )

    def clients_garbage(self, pkt):
        """
        Track clients associated with APs.

        :param pkt: Packet to analyse.
        """
        if (
            pkt.haslayer(Dot11)
            and pkt.getlayer(Dot11).type == 2
            and not pkt.haslayer(EAPOL)
        ):
            sn = pkt.getlayer(Dot11).addr2
            rc = pkt.getlayer(Dot11).addr1
            tgt, ap = (
                (rc, sn)
                if sn in self.bss_counter
                else (sn, rc)
                if rc in self.bss_counter
                else (None, None)
            )

            if (
                tgt
                and tgt not in self.clients
            ):
                for cell in self.cells:
                    if cell["bssid"] == ap:
                        if (
                            re.sub(
                                ":", "", tgt
                            ).lower()
                            not in self.BLACKLIST
                        ):
                            cell[
                                "clients"
                            ] += 1
                            self.clients.append(
                                tgt
                            )
                            self.ALSA_clients[
                                ap
                            ].append(
                                (
                                    tgt,
                                    self.dBM_sig(
                                        pkt
                                    ),
                                )
                            )

    def beac_shift(self, pkt):
        """
        Process beacon frames.

        :param pkt: Packet to process.
        """
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.getlayer(Dot11).addr2
            cap = pkt.sprintf(
                "{Dot11Beacon:%Dot11Beacon.cap%}"
            ).split("+")
            ELTLAYERS = pkt.getlayer(
                Dot11Elt
            )

            if bssid not in self.bss_counter:
                self.bss_counter.add(bssid)
                layer_data = self.enc_shift(
                    cap, ELTLAYERS
                )
                if not self.filtertify(
                    bssid.lower(), layer_data
                ):
                    self.cells.append(
                        {
                            "essid": layer_data[
                                "essid"
                            ],
                            "bssid": bssid,
                            "channel": layer_data[
                                "channel"
                            ],
                            "auth": layer_data[
                                "auth"
                            ],
                            "cipher": layer_data[
                                "cipher"
                            ],
                            "psk": layer_data[
                                "psk"
                            ],
                            "pwr": self.dBM_sig(
                                pkt
                            ),
                            "beacon": pkt,
                            "vendor": org(
                                bssid
                            ).org,
                            "clients": 0,
                        }
                    )
                    self.ALSA_clients[
                        bssid
                    ] = []
            else:
                for ap in self.cells:
                    if ap["bssid"] == bssid:
                        ap["pwr"] = (
                            self.dBM_sig(pkt)
                        )

    def ssid_shift(self, pkt):
        """
        Main handler for handling packets.

        :param pkt: Packet to shift.
        """
        self.beac_shift(pkt)
        self.clients_garbage(pkt)

    def results(self):
        """Return the processed cells."""
        return self.cells

    def run(self):
        """Start sniffing packets."""
        try:
            sniff(
                iface=self.iface,
                prn=self.ssid_shift,
            )
        except Exception as e:
            if self.verbose:
                print(
                    f"An error occurred: {str(e)}"
                )
