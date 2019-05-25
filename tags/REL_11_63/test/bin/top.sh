#!/bin/sh

top -b -n 1 | grep " $1" | awk '{print $(NF-3)}' | sort -n | tail -1

