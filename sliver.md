# Quick Sliver notes

Install sliver (x86_64): `curl https://sliver.sh/install|sudo bash`

Kali has it in apt: `sudo apt install sliver`

- Then you have to make a service file... later.

Run Server: `sliver-server daemon' '--lhost' [ip] `--lport` 31337

Generate operator: `sliver-server operator -l localhost -p 31337 -n spiidey -s ~/.sliver-client/configs/`

Connect to server: `sliver-client` # should auto-connect based on previous config.
