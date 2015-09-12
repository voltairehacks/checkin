# Check-In

The `checkin.py` script runs a continuous `nmap` scan, combining different
scan techniques, to keep an updated table of MAC-to-IP mappings in a JSON file
located at `/netmap.json`.

# Installing

There are no dependencies, besides `nmap` itself. Just copy the script.

# Running

The script needs root privileges to be able to pick up MAC addresses. Run:

    $ sudo python3 checkin.py

You may want to daemonize the process.

# Troubleshooting

If you see too much of this message:

    RTTVAR has grown to over 2.3 seconds, decreasing to 2.0

You may want to allocate some extra memory to the ARP table. Try running:

  sudo /sbin/sysctl -w net.ipv4.neigh.default.gc_thresh3=4096
  sudo /sbin/sysctl -w net.ipv4.neigh.default.gc_thresh2=2048
  sudo /sbin/sysctl -w net.ipv4.neigh.default.gc_thresh1=1024

Double those numbers, if necessary. Any more than that stops making sense, and
the script should be adjusted to run `nmap` more conservatively.
