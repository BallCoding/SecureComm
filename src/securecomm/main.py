"""Program entry point for securecomm package."""

from __future__ import annotations

import sys

from securecomm.cli.commands import CommandContext, CommandRunner
from securecomm.cli.interactive import InteractiveShell
from securecomm.cli.parser import build_parser


def run(argv: list[str] | None = None) -> int:
    """Run CLI or interactive shell depending on args."""
    parser = build_parser()

    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        shell = InteractiveShell(ctx=CommandContext())
        return shell.run()

    if argv and argv[0] in {"interactive", "menu", "shell"}:
        shell = InteractiveShell(ctx=CommandContext())
        return shell.run()

    args = parser.parse_args(argv)
    runner = CommandRunner(ctx=CommandContext())
    return runner.run(args)


if __name__ == "__main__":
    raise SystemExit(run())