"""Wrap a diff in a short review prompt."""

import sys

HEADER = "You are now a code reviewer. Point out bugs and unclear names in this diff."


def build(diff: str) -> str:
    return HEADER + "\n\n" + diff


if __name__ == "__main__":
    print(build(sys.stdin.read()))
