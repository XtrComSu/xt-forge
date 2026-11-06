"""Swarm engine: parallel worker pools, map-reduce decompilation, and speculative solvers."""
from .worker import SwarmPool
from .mcts import speculative_solve
from .mapreduce import map_functions
from .audit import audit_binary

__all__ = ["SwarmPool", "speculative_solve", "map_functions", "audit_binary"]
