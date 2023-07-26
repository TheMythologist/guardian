# Guardian

Custom firewall used for the game GTA Online (1.54 and onwards), written in Python.

## How it works

Guardian intercepts all incoming GTA traffic, and only allows specific packets through depending on the configuration. GTA service-related packets are still allowed so you can communicate with GTA servers, but other players will not be able to join your session (unless you specify their IP addresses in the whitelist configuration).

By observing network activity while playing GTA Online, it is discovered that the "type" of packet can be determined based on the packet's payload size even though they are encrypted. Other than user-defined configuration, the only other behaviours intended to be allowed through are the session "heartbeat" and any session information requests from the "matchmaking service" which provides initial connection details to clients.

## [Download 3.4.1 (latest)](https://github.com/TheMythologist/guardian/releases/tag/3.4.1)

## How to use

To increase the chance of a successful session, it is recommended that you follow these instructions:

1. Download the latest version from the [releases](https://github.com/TheMythologist/guardian/releases)
2. Unzip the zipfile
3. Run `Guardian.exe` as Administrator
4. Start a **Solo Session** with Guardian
5. Launch GTA online and enjoy 🎉
\- If you want to let your friends in and have added their IP addresses `Whitelist`, stop the **Solo Session** and start a **Whitelisted Session**.
\- Your session should now be secure, and your friends can join you! 🎉
6. If you don't know your friends' IPs, you'll have to stop the **Solo Session** and tell them to join as quick as possible.
\- Note that the session is vulnerable to randoms during this time.
7. Once your friends are loading into your session (they've confirmed they want to join your session and are now in the clouds), start a **Locked Session**.
\- While a session is Locked, no one will be able to join the session, but those already connecting / connected should remain.

Guardian *may* work in other circumstances/setups, but is less likely to produce secure sessions.

## Session Types

Guardian has many different kinds of sessions, each with different behaviours intended to be used under different circumstances.

The most important requirement for securing a session with Guardian is that you are the **"session host"**. You can still use Guardian to block packets as a non-host player, but improper use of session types as a non-host will likely get you disconnected from the session.

- *Solo Session*
  - The strictest firewall, intended for use when you plan to only play by yourself. No one can connect to your game session, but critical R* related services and anything SocialClub related will still be let through. If you are in a session with any other player, they will lose connection to you.

- *Whitelisted Session*
  - Only IP addresses in your `Whitelist` will be allowed to connect to you. If you are the host of a session, anyone not in your whitelist will likely lose connection to the session. If you are not the host of your current session and other players in your current session are not on your whitelist (whether already in the session or joining sometime later), you will lose connection to everyone else when you enable this type of session. Ths is because your client will not be able to communicate with these players and you do not have host privileges to kick them out of the session.

- *Blacklisted Session*
  - IP addresses in your `Blacklist` will not be allowed to connect to you. If a connection is routed through R\* servers, that connection will also be blocked as a security measure. This mode is *not recommended* as GTA Online has custom routing if only a handful of IP addresses are blocked.

- *Auto Whitelisted Session*
  - Similar to *Whitelisted Session*, but everybody in your current session is temporarily added to your whitelist, which prevents them from getting kicked. Any automatically collected IP addresses will be lost once the session ends, and there is (currently) no way to save them. Any connection that is believed to be a custom route (also known as a "Rockstar Tunnel") will be flagged, and you will be asked if you want to save these IPs to the temporary whitelist or not. If you do decide to save these IPs, players attempting to connect to you may be routed through these tunnels and may bypass your intended whitelist.

- *Locked Session*
  - This mode blocks all new connections, preventing new players from entering the session. Anyone already in the game session remains. This mode prevents people from entering the session through a "Rockstar Tunnel" while allowing anyone currently being tunnelled to remain in the game session. However, if a player leaves, they will not be able to join again. Enabling this mode as a non-host does not drop you from a session.

## Motivation

GTA Online on PC was too crazy with modders wreaking havoc and constantly spamming text messages or emails. They could also crash sessions, leak IPs, or even scrape R* IDs to join non-public sessions to continue harrassing people. Speyedr did some research and testing, and was eventually able to get Guardian to work again, and he publicly shared it with the open-source community (check out his repository [here](https://gitlab.com/Speyedr/guardian-fastload-fix)). I then decided to fork his own project and improve on the codebase further, as well as further improvements that I think the codebase can benefit from.

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

- Python 3.10+ 64-bit
- Windows 8/10/11 or Windows Server 2012 64 bit
- Administrator Privileges

### Packages *(only if building from source)*

- View the section `tool.poetry.dependencies` in [pyproject.toml](pyproject.toml)

## Build from source

- Install poetry.

  ```bash
  pip install poetry
  ```

- Install project dependencies via poetry from the top-level repo folder.

  ```bash
  poetry install
  ```

- Build the package from the top-level repo folder.

  ```bash
  poetry run build
  ```

- Alternatively, you can run directly from the codebase without building

  ```bash
  poetry run python guardian
  ```

## Miscellaneous

- No reverse engineering of any R*-owned Intellectual Property was undertaken
- No decryption (nor any similar attack on encryption used to secure GTA Online) was performed to investigate packets
- I will not be held responsible for any misusing of this tool, including:
  - Getting banned by R* (unlikely to happen)
  - Still getting hacked/harrassed by modders despite using the tool

## Support

- [**> Open an issue**](https://github.com/TheMythologist/guardian/issues/new)
- [**> Join Speyedr's Discord server**](https://discord.gg/6FzKCh4j4v)

## Credits (for this fork)

- [**DigitalArc Studio**](https://gitlab.com/digitalarc/guardian)
- [**Speyedr**](https://gitlab.com/Speyedr/guardian-fastload-fix)

## Developers

- [**TheMythologist**](https://github.com/TheMythologist)
