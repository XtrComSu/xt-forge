"""Swarm engine: parallel worker pools, map-reduce decompilation, and speculative solvers."""
from .worker import SwarmPool
from .mcts import speculative_solve
from .mapreduce import map_functions

__all__ = ["SwarmPool", "speculative_solve", "map_functions"]
