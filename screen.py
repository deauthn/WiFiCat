import time
from curses import (
    cbreak,
    echo,
    endwin,
    initscr,
    nocbreak,
    noecho,
    window,
)
from os import get_terminal_size
from typing import (
    Dict,
    List,
    Optional,
    Tuple,
)

from screen import keypad, scrollok
from utils import tabulate


class Display:
    """Handles text-based display for WiFi access points and their statistics."""

    shifter_break: bool = False
    shifter_stopped: bool = False
    __wifi_aps: List[Dict] = []

    def __init__(self, verbosity: bool):
        """Initializes the display with the specified verbosity setting.

        Args:
            verbosity (bool): Enables verbose output if True.
        """
        self.verbose = verbosity
        self.screen = (
            self._initialize_curses()
        )

    def __del__(self):
        """Cleans up resources and ends the curses session upon deletion of the object."""
        self.destroy()

    def _initialize_curses(
        self,
    ) -> Optional[window]:
        """Initializes the curses screen.

        Returns:
            curses.window: The initialized screen if successful, None otherwise.
        """
        try:
            screen = initscr()
            noecho()
            cbreak()
            keypad(1)
            scrollok(True)
            return screen
        except Exception as e:
            print(
                f"Error initializing curses: {e}"
            )
            return None

    def destroy(self) -> None:
        """Cleans up the curses window and restores terminal settings."""
        if self.screen:
            self.screen.keypad(0)
            nocbreak()
            echo()
            endwin()

    def current_time(self) -> str:
        """Returns the current local time as a formatted string.

        Returns:
            str: The formatted current local time.
        """
        return time.asctime(
            time.localtime(time.time())
        )

    @staticmethod
    def format_channel(channel: int) -> str:
        """Formats the channel number to ensure it is two digits.

        Args:
            channel (int): The channel number.

        Returns:
            str: The formatted channel number as a string.
        """
        return str(channel).zfill(2)

    def display_shifter(
        self, sniffer, iface_instance
    ) -> None:
        """Displays the list of discovered WiFi access points.

        Args:
            sniffer: Instance of the sniffer to retrieve results from.
            iface_instance: Instance of the interface to get channel information.
        """
        headers = self._get_headers()

        while not self.shifter_break:
            self._refresh_display(
                sniffer,
                iface_instance,
                headers,
            )

        self.shifter_stopped = True

    def _get_headers(self) -> List[str]:
        """Determines the headers for the display based on verbosity level.

        Returns:
            List[str]: A list of headers for the display table.
        """
        if self.verbose:
            return [
                "NO",
                "ESSID",
                "PWR",
                "ENC",
                "CIPHER",
                "AUTH",
                "CH",
                "BSSID",
                "VENDOR",
                "CL",
            ]
        return [
            "NO",
            "ESSID",
            "PWR",
            "ENC",
            "CIPHER",
            "AUTH",
            "CH",
            "BSSID",
        ]

    def _refresh_display(
        self,
        sniffer,
        iface_instance,
        headers: List[str],
    ) -> None:
        """Refreshes the display with the latest WiFi access point information.

        Args:
            sniffer: Instance of the sniffer to retrieve results from.
            iface_instance: Instance of the interface for additional information.
            headers (List[str]): The table headers for display.
        """
        tabulator = []
        self.__wifi_aps = (
            self._gather_access_point_data(
                sniffer
            )
        )

        for ap in self.__wifi_aps:
            ap["essid"] = ap["essid"].rstrip(
                "\x00"
            )
            self._format_access_point_data(
                ap, tabulator
            )

        self.screen.addstr(
            0,
            0,
            f"[{self.format_channel(iface_instance.channel)}] "
            f"Channel [{iface_instance.channel}] "
            f"Time Elapsed [{self.current_time()}] "
            f"Networks Found [{len(tabulator)}]",
        )
        self.screen.addstr(
            1,
            0,
            "\n"
            + tabulate(
                tabulator, headers=headers
            )
            + "\n",
        )
        self.screen.refresh()

    def _gather_access_point_data(
        self, sniffer
    ) -> Tuple[List[int], List[Dict]]:
        """Gathers and organizes access point data from the sniffer.

        Args:
            sniffer: Instance of the sniffer to retrieve results from.

        Returns:
            Tuple[List[int], List[Dict]]: A tuple containing a list of signal strengths and a list of access points.
        """
        signal_list = []
        found_bssids = set()

        for ap in sniffer.results():
            signal_list.append(ap["pwr"])

        signal_list = sorted(
            set(signal_list), reverse=True
        )
        wifi_aps = []

        for signal_strength in signal_list:
            for ap in sniffer.results():
                if (
                    ap["pwr"]
                    == signal_strength
                    and ap["bssid"]
                    not in found_bssids
                ):
                    found_bssids.add(
                        ap["bssid"]
                    )
                    wifi_aps.append(ap)

        return signal_list, wifi_aps

    def _format_access_point_data(
        self,
        ap: Dict,
        tabulator: List[List],
    ) -> None:
        """Formats the access point data for display.

        Args:
            ap (Dict): The access point data to format.
            tabulator (List[List]): The list that will hold formatted access point data.
        """
        if self.verbose:
            tabulator.append(
                [
                    ap["count"],
                    ap["essid"],
                    ap["pwr"],
                    ap["auth"],
                    ap["cipher"],
                    ap["psk"],
                    ap["channel"],
                    ap["bssid"].upper(),
                    ap["vendor"],
                    ap.get("clients", "N/A"),
                ]
            )
        else:
            tabulator.append(
                [
                    ap["count"],
                    ap["essid"],
                    ap["pwr"],
                    ap["auth"],
                    ap["cipher"],
                    ap["psk"],
                    ap["channel"],
                    ap["bssid"].upper(),
                ]
            )

    def clear(self) -> None:
        """Clears the screen for fresh output display."""
        self.screen.clear()

    def get_size(self) -> Optional[int]:
        """Retrieves the size of the terminal window, returning the number of columns.

        Returns:
            Optional[int]: The number of columns in the terminal window, or None if unable to determine.
        """
        try:
            return (
                get_terminal_size().columns
            )
        except OSError:
            return None
