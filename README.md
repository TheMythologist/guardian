## Guardian
Simple custom firewall used for the game GTA5.

This fork uses new methods to drop packets to R*-owned resources that are likely to be tunnelled game traffic, rather than let all R*-owned resources through. The only two behaviours intended to be allowed through from non-whitelisted IPs with this new model are the session "heartbeat" and any session information requests from the "matchmaking service" which provides initial connection details to clients.

By simply observing network activity when playing GTA Online, it was discovered that while all packets were encrypted, the "type" of packet can still be determined from simply checking the packet's payload size. Guardian already uses PyDivert which conveniently supports filtering on individual packets, so only a few minor modifications to the filtering rules were necessary to produce this fork which supports Online 1.54 and onwards.

## Motivation

I never quite liked the idea of firewalled sessions, however modders were targetting a grinding crew I was in by crashing our sessions, leaking our IPs and scraping our R* IDs to join non-public sessions and continue harassing us whenever any of us tried to play Online. So, I did my own research and testing and was eventually able to share a working version with crew members. Now that we have something to defend ourselves, it was suggested that I also fix publicly available whitelisting programs too.

- [Requirements](#requirements)
  - [System](#system)
  - [Packages](#packages)
- [Build from source](#build-from-source)
- [Contributions](#contributions)
- [Changelog](CHANGELOG.md)
- [License](LICENSE)

## Requirements
#### System
- Python 3.6+ 64 bit
- Windows Vista/7/8/10 or Windows Server 2008 64 bit
- Administrator Privileges
#### Packages
- See [requirements.txt](requirements.txt)

## Build from source
Run `make_exe.cmd` or
```
set TCL_LIBRARY=P:\Program Files (x86)\Python36\tcl\tcl8.6
set TK_LIBRARY=P:\Program Files (x86)\Python36\tcl\tk8.6
python setup.py build
```

## Miscellaneous
- Producing this fork took approximately 2 months of casual research and testing to complete.
- No reverse engineering of any R*-owned Intellectual Property was undertaken to produce this fork.
- No decryption (nor any similar attack on encryption used to secure GTA Online) was performed to investigate packets.

## Credits (for this fork)
#### Developers
- [**DintNL**](https://gitlab.com/DintNL): Co-dev, pointed me in the right direction, suggested I make this fork.

#### Guinea Pigs
- MrAlvie
- TKMachine007
- TessioMT
- RDS128
- WristyGolf
- Bulki
- ElkTastic
- Raiulyn
- Cochvik
- n3rdfury

## Contributions
All contributions are helpful, feel free to make a Merge Request.
