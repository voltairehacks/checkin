#!/usr/bin/env python3
import subprocess, json, sys, time, traceback
from pprint import pprint
from datetime import datetime

# This script runs `nmap` repeatedly, and keeps an updated table of ip/mac
# entries in `OUTPUT_FILE`.
OUTPUT_FILE = 'netmap.json'

# `nmap` doesn't always report all devices. The table holds devices found in the
# last `RESULT_EXPIRE_SECS` seconds:
RESULT_EXPIRE_SECS = 3

# `nmap` sometimes freezes. Running it again solves it:
NMAP_TIMEOUT = RESULT_EXPIRE_SECS

# `nmap` prints information in semi-formatted lines, containing phrases:
BEGIN_REPORT = 'Nmap scan report'
MAC_ADDRESS  = 'MAC Address'
END_NMAP     = 'Nmap done'


class Device:
    def __init__(self, ip, mac, last_seen):
        self.ip = ip
        self.mac = mac
        self.last_seen = last_seen

    def __repr__(self):
        return "<Device ip(%s) mac(%s) ls(%s)>" % (self.ip, self.mac, self.last_seen)

    @property
    def expired(self):
        return (datetime.now() - self.last_seen).total_seconds() >= RESULT_EXPIRE_SECS

    def to_entry(self):
        return {
            'ip': self.ip,
            'mac': self.mac,
            'last_seen': self.last_seen.strftime("%Y-%m-%d %H:%M:%S")
        }


def nmap(timeout):
    # TODO I think it's possible to keep a balance between `nmap` speed and
    # results by running parallel nmap instances at different intervals. For
    # example:
    #   $ nmap -sn every 10 seconds
    #   $ nmap -sn --disable-arp-ping every 60 seconds
    # maybe more
    command = "sudo nmap -sn 192.168.0.2-15 192.168.0.50-60"

    try:
        return subprocess.check_output(command.split(), timeout).decode()
    except KeyboardInterrupt:
        raise
    except:
        return ""


def add_devices(nmap_output, timestamp):
    current_ip  = None
    current_mac = None

    for line in nmap_output.split('\n'):
        if BEGIN_REPORT in line:
            # "Nmap scan report for 192.168.0.2"
            current_ip = line.split()[-1]

        elif MAC_ADDRESS in line:
            # "MAC Address: 04:46:65:4D:3B:C7 (Murata Manufacturing Co.)"
            current_mac = line.split()[2]
            devices_by_mac[current_mac] = Device(current_ip, current_mac, timestamp)


def expire_devices():
    now = datetime.now()
    old_devices = dict(devices_by_mac) # make a copy

    for device in old_devices.values():
        if device.expired: del devices_by_mac[device.mac]


def update_netmap():
    while True:
        nmap_output = nmap(timeout = NMAP_TIMEOUT)
        if nmap_output: break

    timestamp = datetime.now()

    add_devices(nmap_output, timestamp)
    expire_devices()


def print_netmap():
    print('---')
    for device in devices_by_mac.values():
        print("* {ip: <20} {mac: <20} {last_seen}".format(**device.to_entry()))


def save_netmap():
    entries = [ device.to_entry() for device in devices_by_mac.values() ]

    with open(OUTPUT_FILE, 'w') as f:
        json.dump(entries, f, indent = 2)


def run_once():
    try:
        update_netmap()
        print_netmap()
        save_netmap()
    except Exception as e:
        traceback.print_exc(file = sys.stderr)


def main():
    print("Check-in started")

    while True:
        run_once()


main()
