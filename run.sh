#!/bin/sh
# This script is for debug only. For production, please use the init script.

twistd -ny dns-filter.py --uid=$(id -u nobody) --gid=$(id -g nobody) --syslog
