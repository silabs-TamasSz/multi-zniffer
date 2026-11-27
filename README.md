# Multi Zniffer

This tool combines multiple PTI data stream to one for Z-Wave Zniffer application

# Requirements

- Wired network access
- One WSTK / WPK board with any Z-Wave capable radio board for all the Z-Wave channels to monitor, at most five: Classic channels 0-2 + LR-A and LR B.
- RAILtest application

## Preparation / Usage

1. Compile the RAILtest application from Simplicity Studio examples (or use the binary if available) - default settings are OK. Flash all the devices with the RAILtest image.
2. Connect the boards to the network which is accessible by the Multi-zniffer tool. 
3. Copy `multi-zniffe.conf.example` to `multi-zniffe.conf` and apply the network host name of the WSTK / WPK boards - if there are less boards, remove the unnecessary ones from the config file. The example config file contains the settings for US Long Range - modify to match the required region.
4. Start `multi-zniffer.py` - it initializes the RAILtest corresponding to the settings in the configuration file
5. Execute the PC Zniffer application and set the machine that runs `multi-zniffer.py` as the host ("Add Zniffer Module Port" in "Capture" menu and select the "Port"). If `multi-zniffer.py` runs on the same computer as the PC Zniffer application, the `localhost` address can be used (`127.0.0.1`)
6. Start capturing in the PC Zniffer application
