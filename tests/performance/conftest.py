"""Shared fixtures for performance tests.

Performance tests do not need DB or Azure connections — they test pure
Python throughput.  No fixtures beyond what pytest provides.
"""
