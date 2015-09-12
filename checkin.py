#!/usr/bin/env python3
import json, sys, time, traceback, subprocess
from pprint import pprint
from datetime import datetime
from threading import Thread
from queue import Queue

# This script runs `nmap` repeatedly, with different arguments, and keeps an
# updated table of ip/mac entries in `OUTPUT_FILE`:
OUTPUT_FILE = 'netmap.json'

# `nmap` doesn't always report all devices. The table holds devices found in the
# last `RESULT_EXPIRE_SECS` seconds:
RESULT_EXPIRE_SECS = 60

# `nmap` sometimes freezes. Running it again solves it:
NMAP_TIMEOUT = 15

# `nmap` prints information in semi-formatted lines, containing phrases:
BEGIN_REPORT = 'Nmap scan report'
MAC_ADDRESS  = 'MAC Address'
END_NMAP     = 'Nmap done'

# `nmap` can yield different results with different scanning techniques. We want
# to detect newly connected devices as fast as possible, but we also want to
# detect all devices eventually. Thus, we need to take different approaches
# simultaneously. This needs to be adjusted based on tests in a real set-up.
COMMON_IPS = '192.168.1.2-15 192.168.1.50-60'
OTHER_IPS  = '192.168.1.16-49 192.168.1.61-150' # NOTE! 151+ left out

NMAP_FLAG_SETS = [
    '-sn %s' % COMMON_IPS,                    # Fastest (ARP scan common ips)
    '-sn %s' % OTHER_IPS,                     # Fast (ARP scan rest of subnet)
    '-sn --disable-arp-ping %s' % COMMON_IPS, # Slow (TCP PING scan common ips)
    '-sn --disable-arp-ping %s' % OTHER_IPS   # Slowest (TCP PING scan rest of subnet)
]


class Device:
    def __init__(self, ip, mac, last_seen):
        self.ip = ip
        self.mac = mac
        self.last_seen = last_seen

    @property
    def expired(self):
        return (datetime.now() - self.last_seen).total_seconds() >= RESULT_EXPIRE_SECS

    def to_entry(self):
        return {
            'ip': self.ip,
            'mac': self.mac,
            'last_seen': self.last_seen.strftime("%Y-%m-%d %H:%M:%S")
        }

    def __repr__(self):
        return "<Device ip(%s) mac(%s) ls(%s)>" % (self.ip, self.mac, self.last_seen)


class Netmap:
    def __init__(self):
        self.devices_by_mac = {}

    def add(self, device):
        self.devices_by_mac[device.mac] = device

    def expire(self):
        old_devices = dict(self.devices_by_mac) # make a copy

        for device in old_devices.values():
            if device.expired: del self.devices_by_mac[device.mac]

    def print(self):
        for device in self.devices_by_mac.values():
            entry = device.to_entry()
            print("* {ip: <20} {mac: <20} {last_seen}".format(**entry))

    def save(self, path):
        entries = [ device.to_entry() for device in self.devices_by_mac.values() ]

        with open(path, 'w') as f:
            json.dump(entries, f, indent = 2)


def nmap(flags, timeout):
    command = "sudo nmap {}".format(flags)
    output  = subprocess.check_output(command.split(), timeout).decode()
    timestamp   = datetime.now()
    current_ip  = None
    current_mac = None

    for line in output.split('\n'):
        if BEGIN_REPORT in line:
            # "Nmap scan report for 192.168.0.2"
            current_ip = line.split()[-1]

        elif MAC_ADDRESS in line:
            # "MAC Address: 04:46:65:4D:3B:C7 (Murata Manufacturing Co.)"
            current_mac = line.split()[2]
            yield Device(current_ip, current_mac, timestamp)


class NetworkMapper(Thread):
    def __init__(self, queue, flags, timeout):
        super().__init__()
        self.stopped = False
        self.queue   = queue
        self.timeout = timeout
        self.flags   = flags

    def run(self):
        while True:
            try:
                devices = list(nmap(self.flags, self.timeout))
            except:
                continue

            if self.stopped: break # break after nmap, before reporting results
            self.queue.put(devices)

    def stop(self):
        self.stopped = True


# traceback.print_exc(file = sys.stderr)

def main():
    print("Check-in started")

    queue   = Queue()
    netmap  = Netmap()
    mappers = [
        NetworkMapper(queue, flags, NMAP_TIMEOUT) for flags in NMAP_FLAG_SETS
    ]

    for mapper in mappers:
        mapper.start()

    while True:
        new_results = queue.get()
        for result in new_results:
            netmap.add(result)

        netmap.expire()
        print('---')
        netmap.print()
        netmap.save(OUTPUT_FILE)

main()
