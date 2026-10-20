#!/usr/bin/env python3
"""TraceVoid - terminal OSINT toolkit for Termux."""
from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import time

try:
    from tracevoid.modules import MODULES
except ModuleNotFoundError as exc:
    if exc.name == "tracevoid":
        print("\n[TraceVoid] Package 'tracevoid' was not found.\n")
        print("Make sure the project has this structure:")
        print("  main.py")
        print("  tracevoid/__init__.py")
        print("  tracevoid/modules.py\n")
        print("Run from the project directory: cd TraceVoid && python main.py")
        raise SystemExit(1)
    raise

# ANSI palette: red/white/gray/green, disabled automatically for redirected output.
USE_COLOR = sys.stdout.isatty() and os.getenv("NO_COLOR") is None


def c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


RED, BRIGHT_RED, WHITE, GRAY, GREEN, YELLOW = "31", "91", "97", "90", "92", "93"
VERSION = "2.0.0"

LOGO = r"""
 _______                       __     _     __
|__   __|                     / _|   (_)   / _|
   | |_ __ __ _  ___ ___  ___| |_ ___ _  | |_ ___
   | | '__/ _` |/ __/ _ \/ __|  _/ _ \ | |  _/ _ \
   | | | | (_| | (_|  __/ (__| ||  __/ | | ||  __/
   |_|_|  \__,_|\___\___|\___|_| \___| |_|_| \___|
"""


def clear() -> None:
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="")


def line(char: str = "─") -> str:
    width = shutil.get_terminal_size((72, 24)).columns
    return char * max(48, min(width, 88))


def header(section: str | None = None) -> None:
    print(c(RED, LOGO))
    print(c(GRAY, f"  NULLKAT DEVELOPMENT  /  PUBLIC OSINT  /  v{VERSION}"))
    print(c(GRAY, line()))
    if section:
        print(c(WHITE, f"  {section.upper()}"))
        print(c(GRAY, line("·")))


def pause(message: str = "Press Enter to return...") -> None:
    try:
        input(c(GRAY, f"\n{message}"))
    except EOFError:
        pass


def loading() -> None:
    print(c(GRAY, "  booting TraceVoid"), end="", flush=True)
    for _ in range(3):
        time.sleep(0.10)
        print(c(RED, "·"), end="", flush=True)
    print(c(GREEN, " online"))


def dependency_status() -> list[tuple[str, bool, str]]:
    checks = [("Python 3.9+", sys.version_info >= (3, 9), "required")]
    for package, label in (("requests", "network modules"), ("phonenumbers", "phone metadata"), ("dns", "DNS records"), ("whois", "WHOIS"), ("PIL", "image metadata")):
        checks.append((package, importlib.util.find_spec(package) is not None, label))
    return checks


def startup_check() -> bool:
    print(c(WHITE, "  STARTUP DIAGNOSTICS"))
    checks = dependency_status()
    for name, ok, note in checks:
        state = c(GREEN, "READY") if ok else c(YELLOW, "OPTIONAL")
        print(f"  [{state}] {name:<13} {c(GRAY, note)}")
    if not sys.version_info >= (3, 9):
        print(c(BRIGHT_RED, "\n  Python 3.9+ is required."))
        return False
    print(c(GRAY, "\n  Modules requiring missing dependencies will show a clear message."))
    return True


def credit() -> None:
    clear(); header("Credit")
    print("  Organization: NullKat Development")
    print("  Developer: undefined")
    print("  Co-developer: undefined")
    print(c(BRIGHT_RED, "\n  WARNING"))
    print("  OSINT can harm privacy when misused to identify, stalk, harass,")
    print("  or abuse information about other people. Respect privacy, use")
    print("  legitimate sources, and comply with applicable law.")
    pause()


def help_menu() -> None:
    clear(); header("Help")
    print("  NAVIGATION")
    print("  • Enter a number from 01-25 to open a module.")
    print("  • C = Credit, H = Help, Q = Exit.")
    print("  • Ctrl+C safely cancels the active operation.")
    print("\n  LIMITATIONS")
    print("  • Network sources are public and use timeouts and redirect limits.")
    print("  • Local modules read files from the device and do not upload them.")
    print("  • No passwords, chat contents, GPS, online status, or ownership claims.")
    print("  • Failed checks are never replaced with fabricated data.")
    pause()


def menu() -> None:
    while True:
        clear(); header("Main Menu  /  25 Modules")
        for index, (name, _) in enumerate(MODULES, 1):
            print(f"  {c(RED, f'{index:02d}')}  {name}")
        print(c(GRAY, line("·")))
        print(f"  {c(GREEN, 'C')} Credit   {c(GREEN, 'H')} Help   {c(GREEN, 'Q')} Exit")
        try:
            choice = input(f"\n  {c(RED, 'tracevoid')} {c(GRAY, '›')} ").strip().lower()
        except EOFError:
            choice = "q"
        if choice == "q":
            print(c(GRAY, "\n  Session closed safely. Stay lawful.\n")); return
        if choice == "c": credit(); continue
        if choice == "h": help_menu(); continue
        if not choice.isdigit() or not 1 <= int(choice) <= len(MODULES):
            print(c(BRIGHT_RED, "\n  Invalid choice. Use 01-25, C, H, or Q.")); time.sleep(0.8); continue
        name, action = MODULES[int(choice) - 1]
        clear(); header(f"Module  /  {name}")
        try:
            action()
        except KeyboardInterrupt:
            print(c(YELLOW, "\n  Operation cancelled by the user."))
        except Exception as exc:
            print(c(BRIGHT_RED, f"\n  Module failed without fabricating results: {type(exc).__name__}: {exc}"))
        pause("Press Enter to return to the menu...")


def main() -> None:
    try:
        clear(); header(); loading(); print()
        if startup_check():
            pause("Press Enter to open the menu...")
            menu()
    except KeyboardInterrupt:
        print(c(GRAY, "\n\n  Session closed safely.\n"))


if __name__ == "__main__":
    main()
