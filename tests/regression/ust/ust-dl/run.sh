#!/bin/sh

LD_PRELOAD="liblttng-ust-dl.so" LD_LIBRARY_PATH=. ./prog
