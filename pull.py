import os
import random
import sys

__log__ = r"""%s

 ____      ____  _   ________  _    ______         _    
|_  _|    |_  _|(_) |_   __  |(_) .' ___  |       / |_  
  \ \  /\  / /  __    | |_ \_|__ / .'   \_| ,--. `| |-' 
   \ \/  \/ /  [  |   |  _|  [  || |       `'_\ : | |   
    \  /\  /    | |  _| |_    | |\ `.___.'\// | |,| |,  
     \/  \/    [___]|_____|  [___]`.____ .'\'-;__/\__/  
%s 
          %sv1.0. Refactored && Recoded by @deauthn%s
"""

__mode__ = """
Syntax:
    $ python main.py [--mode [modes]] [--options]
    $ python main.py --mode 2 -i wlan1mon --verbose -d /path/to/list -w pmkid.txt

Modes:
    #     Description                                 Value
    01    Capture 4-way handshake and crack MIC code    1
    02    Captures and Crack PMKID (PMKID Attack)       2
    03    Perform Manual cracking on available capture types. See --list-types 3
    04    Deauthentication. Disconnect two stations and jam the traffic. 4 

Use -h, --help after -m, --mode to get help on modes.
"""

mode_help_messages = {
    1: """
Mode: 
   01      Capture 4-way handshake and crack MIC code    1

Options:
   Args               Description                      Required
   -h, --help         Show this help manual              NO
   -i, --interface    Monitor Interface to use           YES
   -v, --verbose      Turn off Verbose mode.             NO
   -t, --timeout      Time Delay between two deauth requests. NO
   -d, --dictionary   Dictionary for Cracking            YES
   -w, --write        Write Captured handshake to a separate file NO
       --deauth       Number of Deauthentication frames to send NO 

Filters: 
   -e, --essid         ESSID of listening network
   -b, --bssid         BSSID of target network.
   -c, --channel       Channel interface should be listening on. Default: ALL
    """,
    2: """
Mode: 
   02      Captures and Crack PMKID (PMKID Attack)       1

Options:
   Args               Description                      Required
   -h, --help         Show this help manual              NO
   -i, --interface    Monitor Interface to use           YES
   -v, --verbose      Turn off Verbose mode.             NO
   -d, --dictionary   Dictionary for Cracking            YES
   -w, --write        Write Captured handshake to a separate file NO

Filters: 
   -e, --essid         ESSID of listening network
   -b, --bssid         BSSID of target network.
   -c, --channel       Channel interface should be listening on. Default: ALL
    """,
    3: """
Mode: 
   03    Perform Manual cracking on available capture types. See --list-types    3

Options:
   Args               Description                      Required 
   -h, --help         Show this help manual              NO
       --list-types   List available cracking types      NO
       --type         Type of capture to crack           YES
   -v, --verbose      Turn off Verbose mode.             NO
   -d, --dictionary   Dictionary for Cracking            YES
   -e, --essid        ESSID of target network. 
                      Only for HANDSHAKE Type            YES
   -r, --read         Captured file to crack             YES
    """,
    4: """
Mode:
    04   Deauthentication. Disconnect two stations and jam the traffic. 4

Options:
    Args              Description                      Required
    -h, --help        Show this help manual              NO
    -i, --interface   Monitor Mode Interface to use      YES
    -0, --count       Number of Deauthentication frames to send. '0' specifies unlimited frames YES
        --ap          Access Point MAC Address           NO
        --client      STA (Station) MAC Address          NO
    """,
}

__list__ = """
Types: 
    #         Type            Value
    1         HANDSHAKE       handshake
    2         PMKID           pmkid
"""


class Pully:
    colours = {
        "WHITE": "\033[0m",
        "PURPLE": "\033[95m",
        "CYAN": "\033[96m",
        "DARKCYAN": "\033[36m",
        "BLUE": "\033[94m",
        "GREEN": "\033[92m",
        "YELLOW": "\033[93m",
        "RED": "\033[91m",
        "BOLD": "\033[1m",
        "UNDERLINE": "\033[4m",
        "END": "\033[0m",
        "LINEUP": "\033[F",
    }

    def __init__(self):
        """Initialise the Pully class and check for colour support."""
        if not self.support_colours:
            self.remove_win_colours()

    @property
    def support_colours(self):
        """Check if the terminal supports coloured output."""
        plat = sys.platform
        supported_platform = (
            plat != "Pocket PC"
            and (
                plat != "win32"
                or "ANSICON" in os.environ
            )
        )
        is_a_tty = (
            hasattr(sys.stdout, "isatty")
            and sys.stdout.isatty()
        )
        return (
            supported_platform and is_a_tty
        )

    def remove_win_colours(self):
        """Remove ANSI colour codes for Windows compatibility."""
        for key in self.colours:
            self.colours[key] = ""

    def _print_message(
        self, prefix, colour, statement
    ):
        """Print a message with a specified prefix and colour."""
        print(
            f"{self.colours[colour]}{prefix}{self.colours['END']} {statement}"
        )

    def info(self, statement):
        """Print an info message."""
        self._print_message(
            "[*]", "YELLOW", statement
        )

    def error(self, statement):
        """Print an error message."""
        self._print_message(
            "[!]", "RED", statement
        )

    def up(self, statement):
        """Print an up message."""
        self._print_message(
            "[^]", "BLUE", statement
        )

    def use(self, statement):
        """Print a usage message."""
        self._print_message(
            "[+]", "GREEN", statement
        )

    def question(self, statement):
        """Print a question and return user input."""
        return input(
            f"{self.colours['PURPLE']}[?]{self.colours['END']} {statement}"
        )

    def delete(self, statement):
        """Print a delete message."""
        self._print_message(
            "[#]", "CYAN", statement
        )

    def special(self, statement):
        """Print a special message."""
        self._print_message(
            "[~]", "RED", statement
        )

    def spacer(self, statement):
        """Print a spacer message."""
        print("    ", statement)

    def linebreak(self):
        """Print a line break."""
        print("\n")

    def right(self, statement):
        """Print a rightward message."""
        self._print_message(
            "[>]", "DARKCYAN", statement
        )

    def lineup(self):
        """Move the cursor up one line."""
        sys.stdout.write(
            self.colours["LINEUP"]
        )

    def random_picker(self):
        """Return a random colour for output."""
        seq = (
            self.colours["RED"],
            self.colours["GREEN"],
            self.colours["YELLOW"],
            self.colours["BLUE"],
        )
        return random.choice(seq)

    def logo(self):
        """Print the logo."""
        print(
            __log__
            % (
                self.colours["BOLD"]
                + self.random_picker(),
                self.colours["END"],
                self.colours["BOLD"],
                self.colours["END"],
            )
        )

    def help(self, mode):
        """Print help information for a specific mode."""
        print(
            mode_help_messages.get(
                mode, "Invalid Mode"
            )
        )

    def modes(self):
        """Print available modes."""
        print(__mode__)

    def list_types(self):
        """Print available capture types."""
        print(__list__)


if __name__ == "__main__":
    pully = Pully()
    pully.logo()
    pully.modes()
    pully.help(1)
