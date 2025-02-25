# WiFiCat


WifiCat is a powerful, basic tool designed for comprehensive WiFi (WPA/WPA2) network penetration testing.  Built upon the robust Scapy packet manipulation library in Python, WifiCat provides a suite of functionalities, each intricately woven together to offer unparalleled capabilities.  Almost every process within WifiCat leverages Scapy's layers and functions, creating a seamless and efficient workflow.  The exception to this is wireless interface channel switching, which utilises the native Linux command `iwconfig`, requiring sudo privileges for execution.

Currently, WifiCat boasts four distinct operational modes to tackle target networks: two online cracking methods and two offline modes. The offline modes are specifically designed to crack hashes captured during the online cracking phases.  One online mode employs a deauthentication attack, effectively disrupting the target network and serving as a potent jamming countermeasure.  The tool's versatility extends to various Linux platforms, although optimal performance is achieved with a TP-Link WN727N wireless adapter.

**Important Note:** WifiCat is under active development. The existing code is undergoing continuous refinement. As such, please be aware that full functionality may not always be guaranteed at this stage. (This is also a fork of a tool called wifibroot which I found that hasnt been worked on in years. All of the code included in the repo has been recoded by me.)
