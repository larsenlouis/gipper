# gipper: Google IP groPER

**TL;DR**: Jump to **[`Install Guide`](#install-guide)**,  **[`Configure`](#configure)** and  **[`Scan`](#scan)**.

gipper is actually

* a suite of the aggressively fast TCP port scanner [masscan](https://github.com/robertdavidgraham/masscan) and some python 3 helper scripts.
* a google ip scanner with offline certificate checker that can tell gws and gvs.

gipper is likely

* for people who do not have self-control.
* for people who do have headless *nix servers.

## Install Guide

if you are Windows user, gipper MIGHT work with a shitload of compatibility effort. Pull requests are welcomed.

### Get the Code
```
git clone --recursive https://github.com/larsenlouis/gipper.git
```

### Install masscan

Please DO NOT clone the original `masscan` code. This is a tiny mod of the masscan. Further modification is considered.

On Debian/Ubuntu:

`sudo apt install gcc make libpcap-dev`

* go to masscan folder. `cd masscan`

* clean stuff. `make clean`

* build masscan. `make -j`

### Install Python dependencies

#### Install Python 3 and pip


```
# install python 3 and pip
sudo apt install python3 python3-pip

# change to your favorite pypi mirror
nano ~/.pip/pip.conf

# upgrade pip to the lastest version
sudo pip3 install --upgrade pip
```


#### Install dependencies
`sudo pip3 install requests pem pyopenssl`

#### Make it executable
`chmod +x scan.py`

# Configure

masscan needs a seperate LAN ip, open masscan.conf, and edit:
```
adapter-ip = <LAN IP>
```

# Scan
```
Usage: scan.py <transmit rate> <countryCode1> <countryCode2>... <countryCodeN>
```
Example: `scan.py 2000 hk`

This will scan all the Hong Kong ips at the speed of 2000 pps

Country codes is available at https://en.wikipedia.org/wiki/ISO_3166-1

## Scan Best Practice

### Transmit Rate Control

* Transmit rate(aka rate) is the packet sending speed. 2000 pps will consume ~100KiB/s uplink. Test your uplink speed and set to 80% of uplink speed is advised.

* If you want to reach 2 million pps, you need to install PF_RING driver, according to the [masscan README](https://github.com/robertdavidgraham/masscan#pf_ring).
    
* Your network will be melted down if your transmit rate is too high. Some response may be timed out and your other network applications will be jammed.

### IPs per Run
* South Korea has 100 million+ ips. Gipper will spend 18 hours+ to scan the whole country at the speed of 2000 pps.

### Log Size
* The same South Korea scan above will occupy 1.5 GiB of disk space.


# TODO
* Log output to stdout and parsed by Python in real time. (needs C language coder)
* ASN info lookup of target hosts. (needs time)
