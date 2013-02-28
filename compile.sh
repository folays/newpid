#!/bin/sh

set -ex

cc -o newpid unshare_pid.c -lutil
