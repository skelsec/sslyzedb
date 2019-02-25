#!/usr/bin/env python3

def a(x):
	if x is None:
		return 'N/A'
	return x

def b(x, sep = ','):
	if x is None:
		return 'N/A'
	return sep.join(x)