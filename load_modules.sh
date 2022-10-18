#!/bin/bash

sudo insmod ./latency_tracker.ko
sudo insmod ./latency_tracker_begin_end.ko
sudo insmod ./latency_tracker_span_latency.ko
