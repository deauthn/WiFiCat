import binascii
import hashlib
import hmac
import re
import string

from pbkdf2 import PBKDF2
from scapy.layers.dot11 import Dot11, Raw
from scapy.layers.eap import EAPOL

from pull import Pully

pull = Pully()


class PSK:
    __NULL_ = b"\x00"
    __PKE_ = b"Pairwise key expansion"

    def __init__(
        self,
        eapol,
        essid,
        enc,
        dictionary,
        verbose,
        key=None,
    ):
        self.__eapols = eapol[:4]
        self.key = key
        self.mic = binascii.hexlify(
            self.__eapols[1]
            .getlayer(Raw)
            .load
        )[154:186]
        self.essid = essid
        self.encryption = enc
        self.dict = dictionary
        self.verbose = verbose
        self.d_passes = self.create_d_passes(
            self.__eapols[1]
            .getlayer(Dot11)
            .addr2
        )
        self.__organize()

    @property
    def cracked(self):
        return self.__cracked[0]

    @property
    def cracked_pass(self):
        return self.__cracked[1]

    def create_d_passes(
        self, mac: str
    ) -> list:
        """Create a list of possible password variations based on MAC address."""
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

    def __organize(self):
        """Organize key aspects from the EAPOL packets."""
        self.ap = binascii.a2b_hex(
            self.__eapols[0]
            .getlayer(Dot11)
            .addr2.replace(":", "")
            .lower()
        )
        self.cl = binascii.a2b_hex(
            self.__eapols[0]
            .getlayer(Dot11)
            .addr1.replace(":", "")
            .lower()
        )
        self.aNONCE = binascii.a2b_hex(
            binascii.hexlify(
                self.__eapols[0]
                .getlayer(Raw)
                .load
            )[26:90]
        )
        self.cNONCE = binascii.a2b_hex(
            binascii.hexlify(
                self.__eapols[1]
                .getlayer(Raw)
                .load
            )[26:90]
        )
        self.key_data = (
            min(self.ap, self.cl)
            + max(self.ap, self.cl)
            + min(self.aNONCE, self.cNONCE)
            + max(self.aNONCE, self.cNONCE)
        )

        eapol = self.__eapols[1].getlayer(
            EAPOL
        )
        self.version = chr(eapol.version)
        self.type = chr(eapol.type)
        self.len = chr(eapol.len)

        self.payload = binascii.a2b_hex(
            binascii.hexlify(
                self.version.encode()
                + self.type.encode()
                + self.__NULL_
                + self.len.encode()
                + binascii.a2b_hex(
                    binascii.hexlify(
                        self.__eapols[1]
                        .getlayer(Raw)
                        .load
                    )[:154]
                )
                + self.__NULL_ * 16
                + binascii.a2b_hex(
                    binascii.hexlify(
                        self.__eapols[1]
                        .getlayer(Raw)
                        .load
                    )[186:]
                )
            )
        )

    def custom_prf512(
        self, key, A, B
    ) -> bytes:
        """Custom Pseudo Random Function based on HMAC."""
        blen = 64
        R = b""
        for i in range(
            (blen * 8 + 159) // 160
        ):
            hmacsha1 = hmac.new(
                key,
                A
                + bytes([0x00])
                + B
                + bytes([i]),
                hashlib.sha1,
            )
            R += hmacsha1.digest()
        return R[:blen]

    def hash(self, password: str) -> tuple:
        """Generate PMK, PTK, MIC using the given password."""
        pmk = PBKDF2(
            password, self.essid, 4096
        ).read(32)
        ptk = self.custom_prf512(
            pmk, self.__PKE_, self.key_data
        )

        mic = (
            hmac.new(
                ptk[:16],
                self.payload,
                hashlib.md5,
            ).digest()
            if self.encryption == "WPA"
            else hmac.new(
                ptk[:16],
                self.payload,
                hashlib.sha1,
            ).digest()
        )
        if (
            self.mic == binascii.hexlify(mic)
            or self.mic
            == binascii.hexlify(mic)[:32]
        ):
            self.__cracked = (True, password)
            return pmk, ptk, mic
        return pmk, ptk, mic

    def print_password(
        self,
        current_pass: str,
        last_pass: str,
    ) -> str:
        """Format password output for display."""
        len_a, len_b = (
            len(current_pass),
            len(last_pass),
        )
        if len_a > len_b:
            return last_pass + " " * (
                len_a - len_b
            )
        return last_pass

    def pass_list(self) -> list:
        """Retrieve the list of passwords to try."""
        if self.key is None:
            with open(
                self.dict, "r"
            ) as file:
                return (
                    self.d_passes
                    + file.readlines()
                )
        return [
            key.strip()
            for key in self.key.split(",")
        ]

    def brute_force(self):
        """Brute force the password using the provided dictionary."""
        last_pass, count = "", 0
        for password in self.pass_list():
            (
                self.C_PMK,
                self.C_PTK,
                self.C_MIC,
            ) = self.hash(
                password.rstrip("\n")
            )
            self.C_PASS, count = (
                password.rstrip("\n"),
                count + 1,
            )

            pull.up(
                f"Current Password: {self.print_password(last_pass, password.rstrip('\n'))}"
            )
            last_pass = password.rstrip("\n")

            if self.cracked:
                return (
                    self.cracked_pass,
                    self.hexdump(self.C_PMK),
                    self.hexdump(self.C_PTK),
                    self.hexdump(self.C_MIC),
                )
            elif count < len(
                self.pass_list()
            ):
                pull.lineup()

        return self.cracked_pass, "", "", ""

    def hexdump(
        self,
        src: bytes,
        length: int = 16,
        sep: str = ".",
    ) -> str:
        """Convert binary data into a hex string with a printable representation."""
        display = (
            string.digits
            + string.ascii_letters
            + string.punctuation
        )
        filter_chars = "".join(
            (
                x if x in display else "."
                for x in map(chr, range(256))
            )
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
                f"{c:08x}:  {hex_str:<{length * 3}} |{printable}|\n"
            )
        return "".join(lines)


class eAPoL:
    def __init__(self, bss: str):
        self.bssid = bss
        self.__eapols = [
            None,
            None,
            None,
            None,
        ]

    def check(self, pkt) -> bool:
        """Check the EAPOL packet and categorize it."""
        fNONCE = b"0" * 32
        fMIC = b"0" * 32

        if pkt.haslayer(EAPOL):
            __sn = pkt[Dot11].addr2
            __rc = pkt[Dot11].addr1
            to_DS = (
                pkt.getlayer(Dot11).FCfield
                & 0x1
                != 0
            )
            from_DS = (
                pkt.getlayer(Dot11).FCfield
                & 0x2
                != 0
            )

            if __sn == self.bssid:
                tgt = __rc
            elif __rc == self.bssid:
                tgt = __sn
            else:
                return False

            nonce = binascii.hexlify(
                pkt.getlayer(Raw).load
            )[26:90]
            mic = binascii.hexlify(
                pkt.getlayer(Raw).load
            )[154:186]

            if from_DS:
                if (
                    __sn == self.bssid
                    and __rc == tgt
                    and nonce != fNONCE
                    and mic == fMIC
                ):
                    self.__eapols[0] = pkt
                elif (
                    __sn == self.bssid
                    and __rc == tgt
                    and nonce != fNONCE
                    and mic != fMIC
                ):
                    self.__eapols[2] = pkt
            elif to_DS:
                if (
                    __sn == tgt
                    and __rc == self.bssid
                    and nonce != fNONCE
                    and mic != fMIC
                ):
                    self.__eapols[1] = pkt
                elif (
                    __sn == tgt
                    and __rc == self.bssid
                    and nonce == fNONCE
                    and mic != fMIC
                ):
                    self.__eapols[3] = pkt

        return all(self.__eapols)

    @property
    def get_eapols(self) -> tuple:
        """Get collected EAPOL packets."""
        return tuple(self.__eapols)
