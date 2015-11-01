#!/bin/sh
# This script is for debug only. For production, please use the init script.

export DNS_FILTER_CONF=dns-filter.json
twistd -ny dns-filter.py
