# Guardian

![Logo](logo.ico)

Simple custom firewall used for the game GTA5.

This fork uses new methods to drop packets to R*-owned resources that are likely to be tunnelled game traffic, rather than let all R*-owned resources through. The only two behaviours intended to be allowed through from non-whitelisted IPs with this new model are the session "heartbeat" and any session information requests from the "matchmaking service" which provides initial connection details to clients.

By simply observing network activity when playing GTA Online, it was discovered that while all packets were encrypted, the "type" of packet can still be determined from simply checking the packet's payload size. Guardian already uses PyDivert which conveniently supports filtering on individual packets, so only a few minor modifications to the filtering rules were necessary to produce this fork which supports Online 1.54 and onwards.

## [Download 3.1.0b5 (latest)](https://github.com/TheMythologist/guardian/releases/tag/3.1.0b5)

## Usage

To increase the chance of a successful session, it is recommended that you follow these instructions:

1. Run `Guardian.exe` as Administrator.
2. Load into Single Player.
3. Start a **Solo Session** with Guardian.
4. Load into GTA Online.  
\- If you want access to Public Session Freemode activites, make sure you choose `Go` to attempt to join a Public Session.
5. Once you've loaded into Online, you should now be in a Freemode Session by yourself.  
\- If you want to let your friends in and have added their IP addresses `Lists -> Custom`, stop the **Solo Session** and start a **Whitelisted Session**.  
\- Your session should now be secure, and your friends can join you! 🎉
6. If you don't know your friends' IPs, you'll have to stop the **Solo Session** and tell them to join as quick as possible.  
\- Note that the session is vulnerable to randoms during this time.
7. Once your friends are loading into your session (they've confirmed they want to join your session and are now in the clouds), start a **Locked Session**.  
\- While a session is Locked, no one will be able to join the session, but those already connecting / connected should remain.

Guardian *may* work in other circumstances / setups, but is less likely to produce secured sessions.

## Session Types

Guardian has many different kinds of sessions, each with different behaviours intended to be used under different circumstances.

The most important requirement for securing a session with Guardian is that you are the **"session host"**. You can still use Guardian to block packets as a non-host player, but improper use of session types as a non-host will likely get you disconnected from the session.

- *Solo Session*
  - The strictest firewall, intended for use when you plan to only play by yourself. No one can connect to your game session, but critical R* related services and anything SocialClub related will still be let through. If you are in a session with any other player, they will lose connection to you.

- *Whitelisted Session*
  - Only IP addresses in your Custom list `Lists -> Custom -> Add` will be allowed to connect to you. If you are the host of a session, anyone not on your Custom list will likely lose connection to the session. If you are non-host and enable this type of session and another player in your game session is not on your Custom list (whether already in the session or joining some time later), you will lose connection to everyone else, as your client won't be able to communicate with that player and you do not have host privileges to keep them out of the session.

- *Blacklisted Session*
  - IP addresses in your Blacklist list `Lists -> Blacklist -> Add` will not be allowed to connect to you. If a connection is routed through R\* servers, that connection will also be blocked as a security measure. This mode is *not recommended* as GTA V has custom routing if only a handful of IP addresses are blocked.

- *Auto Whitelisted Session*
  - Similar to *Whitelisted Session*, but everybody in the session is temporarily added to your whitelist, which means they won't be kicked. Any automatically collected IPs will be lost once the session ends, and there is (currently) no way to save them. Any connection that is believed to be a custom route (also known as a "Rockstar Tunnel") will be flagged, and you will be asked if you want to save these IPs to the temporary whitelist or not. If you do decide to save these IPs, players attempting to connect to you may be routed through these tunnels and may bypass your intended whitelist.

- *Locked Session*
  - This mode blocks all new connections, preventing new players from entering the game session. Anyone already in the game session remains, and this mode prevents people from entering the session through a "Rockstar Tunnel" while allowing anyone currently being tunnelled to remain in the game session. However, if a player leaves they will not be able to get back in (unless you stop the *Locked Session_, of course). Enabling this mode as a non-host does _not* drop you from a session.

## Motivation

I never quite liked the idea of firewalled sessions, however modders were targetting a grinding crew I was in by crashing our sessions, leaking our IPs and scraping our R* IDs to join non-public sessions and continue harassing us whenever any of us tried to play Online. So, I did my own research and testing and was eventually able to share a working version with crew members. Now that we have something to defend ourselves, it was suggested that I also fix publicly available whitelisting programs too.

- [Requirements](#requirements)
  - [System](#system)
  - [Packages](#packages-only-if-building-from-source)
- [Build from source](#build-from-source)
- [Miscellaneous](#miscellaneous)
- [Credits](#credits-for-this-fork)
  - [Developers](#developers)
- [License](LICENSE)

## Requirements

### System

- Python 3.9/10 64 bit
- Windows 8/10/11 or Windows Server 2012 64 bit
- Administrator Privileges

### Packages *(only if building from source)*

- View the section `tool.poetry.dependencies` in [pyproject.toml](pyproject.toml)

## Build from source

- Install poetry.
`pip install poetry`
- Install project dependencies
`poetry install`
- Open a command prompt in the top-level repo folder and run `poetry run python setup.py build`.
  - If python cannot be found, you will need to provide the full location of `python.exe` instead. Your command prompt will still need to be in the same directory as `setup.py` though.

## Miscellaneous

- This fork's initial release took about 2 months of casual research and testing to complete.
- No reverse engineering of any R*-owned Intellectual Property was undertaken to produce this fork.
- No decryption (nor any similar attack on encryption used to secure GTA Online) was performed to investigate packets.

## Support

- [**> Open an issue**](https://github.com/TheMythologist/guardian/issues/new)
- [**> Join Speyedr's Discord server**](https://discord.gg/6FzKCh4j4v)

## Credits (for this fork)

- [**DigitalArc Studio**](https://gitlab.com/digitalarc/guardian)
- [**Speyedr**](https://gitlab.com/Speyedr/guardian-fastload-fix)

## Sponsors

- [DarkViperAU](https://www.youtube.com/@DarkViperAU)
- TessioMT
- AnExtraSleepyKitty
- Harald414

## Developers

- [**TheMythologist**](https://github.com/TheMythologist)
