# PF_RING to Mongo

[![Project Status: Unsupported – The project has reached a stable, usable state but the author(s) have ceased all work on it. A new maintainer may be desired.](https://www.repostatus.org/badges/latest/unsupported.svg)](https://www.repostatus.org/#unsupported)  [![Build Status](https://travis-ci.org/protectus/pfring-to-mongo.svg?branch=master)](https://travis-ci.org/protectus/pfring-to-mongo)

## Introduction

For many years, my dad, Pete Garvin, ran a small network security consulting business called Protectus.  This company provided a product called the Sentry, a network monitoring and analysis platform built on commodity hardware, delivered to small and mid-sized businesses throughout the east-central US.

The core technical abilities of the Sentry were two-fold:

- Capture data off the wire, perform preliminary analysis and aggregation, and dump into MongoDB
- Provide a web app view into the data captured by the Sentry

It could do other things too, like IDS alerts, latency graphs, rudimatry mapping of IPs and ports to hosts and services, etc.  It's a little long in tooth now, but in 2013 it was hands-down the best network traffic + performance + IDS analysis tool on the market for small-mid-sized businesses.

This repository represents most of the data ingest pipeline, which was largely built off the capabilities of pcap, and later, PF_RING.  The initial ingest implimentation was in Python, switching to Cython when we began monitoring larger pipes of data.  This library was originally called Trafcap, but we considered that name to be too opaque for public release.  Thus, this open source release is called pfring-to-mongo.

Dad died the fall of 2019, and only now in the spring of 2020 am I coming back to finish the job.  The project is scaled way back, and there are lots of loose ends.  We had intended to use this open-sourced tool within our own continuing products, and to really polish up it's usage before release. Instead, this release attempts to provide just enough information for a curious individual to maybe kick the tires.

## Dependencies

We've only ever run this against 64-bit Debian-based systems.  Other flavors of linux probably work, but your milage may vary.

You'll need a Mongo server to write to.  I think the tool is probably hard-coded to connect to the local Mongo server.  No support for connecting to an off-host database.  The most recent version of Mongo we've tested against is 3.6.

You'll also need PF_RING installed on your machine.

## Installation

TODO (Need to release a wheel file).  In the meantime, you can build from scratch by following the "Developing" section below.

## Usage

TODO - current implimentation relies on a config file that lives in a very specific location. Need to work around that before demonstrating usage.


## Developing

1. Install Python dev headers (because this involves a C extension)
2. Install cython: `pip install cython`
3. Install specific library dependencies, unless you're feeling adventurous. `pip install -r requirements.txt`
3. Install the [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) kernel module and userspace libraries from ntop.  Vanilla PF_RING is fine, no need for ZC.
4. `python setup.py install`

With any luck, Cython will complete, compilation will complete, and you'll have a brand-spanking-new installed module called trafcap.
