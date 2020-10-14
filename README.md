# log-utils
Tools to act on log output in real time

- **Logsneak**: detect ssh login attempts and temporarily blackhole the source IP
- **DNStraq**: take dnsmasq log output and convert it to transaction logs
- **DNSQLtraq**: take dnsmasq log output, convert it to transactions, and store them in a database

Each util has a sh script file (do the thing) and a rc.d file (tell rc.d based \*nix how to run the script daemon-style)

Developed originally for CentOS 6, so it works with init.d service management, but not systemd.

Since sshd logs vary based on configuration (and defaults per distro), YMMV and you may need to fine-tune logsneak.
