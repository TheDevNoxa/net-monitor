#!/usr/bin/env python3
"""
passgen — Secure password & passphrase generator
Author : Noxa (Valentin Lagarde)
Usage  : python3 passgen.py
         python3 passgen.py --length 24 --count 5
         python3 passgen.py --passphrase --words 5
"""

import argparse
import secrets
import string
import math
import os

WORDLIST_URL = "https://raw.githubusercontent.com/EFF/BIP39-French/master/french.txt"

BUILTIN_WORDS = [
    "soleil","montagne","rivière","château","forêt","océan","nuage","étoile",
    "dragon","pirate","robot","fusée","cristal","labyrinthe","tonnerre",
    "cascade","volcan","galaxie","mystère","horizon","tempête","lumière",
    "ombre","flamme","glacier","désert","jungle","temple","cratère","abysse",
    "cipher","kernel","proxy","socket","daemon","vector","buffer","packet",
    "signal","matrix","binary","router","bridge","mirror","portal","nexus",
    "vault","cipher","token","beacon","sector","turret","zenith","apex",
]

CHARS_LOWER   = string.ascii_lowercase
CHARS_UPPER   = string.ascii_uppercase
CHARS_DIGITS  = string.digits
CHARS_SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?"
CHARS_AMBIGUOUS = "0OlI1"


def entropy_bits(length: int, charset_size: int) -> float:
    if charset_size <= 0:
        return 0.0
    return length * math.log2(charset_size)


def strength_label(bits: float) -> str:
    if bits < 40:  return "WEAK"
    if bits < 60:  return "MODERATE"
    if bits < 80:  return "STRONG"
    if bits < 100: return "VERY STRONG"
    return "EXCELLENT"


def generate_password(length: int = 16,
                      use_upper: bool = True,
                      use_digits: bool = True,
                      use_special: bool = True,
                      no_ambiguous: bool = False) -> str:
    charset = CHARS_LOWER
    if use_upper:   charset += CHARS_UPPER
    if use_digits:  charset += CHARS_DIGITS
    if use_special: charset += CHARS_SPECIAL
    if no_ambiguous:
        charset = "".join(c for c in charset if c not in CHARS_AMBIGUOUS)

    while True:
        pwd = "".join(secrets.choice(charset) for _ in range(length))
        # Ensure at least one char from each required class
        if use_upper   and not any(c in CHARS_UPPER   for c in pwd): continue
        if use_digits  and not any(c in CHARS_DIGITS  for c in pwd): continue
        if use_special and not any(c in CHARS_SPECIAL for c in pwd): continue
        return pwd


def generate_passphrase(word_count: int = 4,
                        separator: str = "-",
                        capitalize: bool = True,
                        add_number: bool = True) -> str:
    words = [secrets.choice(BUILTIN_WORDS) for _ in range(word_count)]
    if capitalize:
        words = [w.capitalize() for w in words]
    phrase = separator.join(words)
    if add_number:
        phrase += separator + str(secrets.randbelow(9000) + 1000)
    return phrase


def generate_pin(length: int = 6) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def generate_hex_key(bits: int = 256) -> str:
    return secrets.token_hex(bits // 8)


COLORS = {
    "EXCELLENT":   "\033[92m",
    "VERY STRONG": "\033[92m",
    "STRONG":      "\033[93m",
    "MODERATE":    "\033[94m",
    "WEAK":        "\033[91m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def print_password(pwd: str, charset_size: int) -> None:
    bits = entropy_bits(len(pwd), charset_size)
    label = strength_label(bits)
    color = COLORS.get(label, "")
    bar_filled = min(40, int(bits / 128 * 40))
    bar = "█" * bar_filled + "░" * (40 - bar_filled)
    print(f"  {BOLD}{pwd}{RESET}")
    print(f"  Entropy : {bits:.1f} bits  [{bar}]  {color}{label}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="Secure password & passphrase generator")
    subp = parser.add_subparsers(dest="mode", help="Generation mode")

    # password mode
    pp = subp.add_parser("password", help="Generate random password(s)")
    pp.add_argument("--length",       type=int,  default=16, help="Password length (default: 16)")
    pp.add_argument("--count",        type=int,  default=1,  help="Number of passwords to generate")
    pp.add_argument("--no-upper",     action="store_true",   help="Exclude uppercase")
    pp.add_argument("--no-digits",    action="store_true",   help="Exclude digits")
    pp.add_argument("--no-special",   action="store_true",   help="Exclude special chars")
    pp.add_argument("--no-ambiguous", action="store_true",   help="Exclude 0/O/l/I/1")

    # passphrase mode
    ph = subp.add_parser("passphrase", help="Generate word-based passphrase(s)")
    ph.add_argument("--words",     type=int, default=4,   help="Number of words (default: 4)")
    ph.add_argument("--count",     type=int, default=1,   help="Number of passphrases")
    ph.add_argument("--separator", default="-",           help="Word separator (default: -)")
    ph.add_argument("--no-number", action="store_true",   help="Don't append a number")
    ph.add_argument("--no-cap",    action="store_true",   help="Don't capitalize words")

    # pin mode
    pn = subp.add_parser("pin", help="Generate numeric PIN")
    pn.add_argument("--length", type=int, default=6, help="PIN length (default: 6)")
    pn.add_argument("--count",  type=int, default=1)

    # key mode
    pk = subp.add_parser("key", help="Generate hex API key / secret")
    pk.add_argument("--bits",  type=int, default=256, help="Key size in bits (default: 256)")
    pk.add_argument("--count", type=int, default=1)

    args = parser.parse_args()

    # Default to password if no mode given
    if not args.mode:
        args.mode = "password"
        args.length = 16
        args.count  = 5
        args.no_upper = args.no_digits = args.no_special = args.no_ambiguous = False

    print()

    if args.mode == "password":
        charset_size = 26
        if not args.no_upper:   charset_size += 26
        if not args.no_digits:  charset_size += 10
        if not args.no_special: charset_size += len(CHARS_SPECIAL)
        for _ in range(args.count):
            pwd = generate_password(
                length=args.length,
                use_upper=not args.no_upper,
                use_digits=not args.no_digits,
                use_special=not args.no_special,
                no_ambiguous=args.no_ambiguous,
            )
            print_password(pwd, charset_size)

    elif args.mode == "passphrase":
        for _ in range(args.count):
            phrase = generate_passphrase(
                word_count=args.words,
                separator=args.separator,
                capitalize=not args.no_cap,
                add_number=not args.no_number,
            )
            print_password(phrase, len(BUILTIN_WORDS))

    elif args.mode == "pin":
        for _ in range(args.count):
            pin = generate_pin(args.length)
            print(f"  {BOLD}{pin}{RESET}  (entropy: {entropy_bits(args.length, 10):.1f} bits)")
        print()

    elif args.mode == "key":
        for _ in range(args.count):
            key = generate_hex_key(args.bits)
            print(f"  {BOLD}{key}{RESET}")
            print(f"  {args.bits} bits of entropy\n")


if __name__ == "__main__":
    main()
