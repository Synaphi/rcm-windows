"""Content decks for the Ray Cluster Manager status board.

The board deliberately mixes useful diagnostics with small low-resolution
moments.  Math lines are generated from checked number-theory predicates so the
"math radio" can be playful without making claims it cannot back up.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import random


MATH_TARGET = 1000
TECH_TARGET = 1000
BOARD_TARGET = 1000
SCENE_TARGET = 100


@dataclass(frozen=True)
class PixelScene:
    key: str
    frames: tuple[tuple[str, ...], ...]
    caption: str
    color: str = "#d0a000"
    accent: str = "#40c0ff"


def _dedupe(lines):
    seen = set()
    out = []
    for line in lines:
        line = " ".join(str(line).split())
        if not line or line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    limit = math.isqrt(n)
    f = 5
    while f <= limit:
        if n % f == 0 or n % (f + 2) == 0:
            return False
        f += 6
    return True


def _prime_factors(n: int) -> list[int]:
    factors = []
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.append(d)
            n //= d
        d = 3 if d == 2 else d + 2
    if n > 1:
        factors.append(n)
    return factors


def _proper_divisor_sum(n: int) -> int:
    if n <= 1:
        return 0
    total = 1
    root = math.isqrt(n)
    for d in range(2, root + 1):
        if n % d == 0:
            total += d
            other = n // d
            if other != d:
                total += other
    return total


def _is_happy(n: int) -> bool:
    seen = set()
    while n != 1 and n not in seen:
        seen.add(n)
        n = sum(int(ch) * int(ch) for ch in str(n))
    return n == 1


def _is_kaprekar(n: int) -> tuple[bool, int, int]:
    if n < 1:
        return False, 0, 0
    sq = n * n
    digits = len(str(n))
    power = 10 ** digits
    left, right = divmod(sq, power)
    return right > 0 and left + right == n, left, right


def _is_narcissistic(n: int) -> bool:
    digits = str(n)
    p = len(digits)
    return sum(int(ch) ** p for ch in digits) == n


def _fib_numbers(limit: int) -> list[int]:
    vals = [0, 1]
    while vals[-1] < limit:
        vals.append(vals[-1] + vals[-2])
    return vals


def build_math_lines(target: int = MATH_TARGET) -> list[str]:
    lines = [
        "NUMBER 8128 :: perfect; its proper divisors walk out and return exactly 8128.",
        "NUMBER 7523 :: prime, safe prime, and its reflection 3257 is prime too.",
        "NUMBER 6 :: the smallest perfect number balances as 1+2+3.",
        "NUMBER 28 :: perfect; 1+2+4+7+14 lands back on 28.",
        "NUMBER 496 :: perfect; Euclid's old machinery still hums here.",
        "NUMBER 33550336 :: perfect; big, even, and still exactly balanced.",
        "NUMBER 1729 :: taxicab; 1^3+12^3 and 9^3+10^3 both arrive there.",
        "NUMBER 6174 :: Kaprekar's constant for four-digit sorting rituals.",
        "NUMBER 153 :: narcissistic; 1^3+5^3+3^3 returns 153.",
        "NUMBER 1089 :: reverse-subtract arithmetic likes turning around here.",
        "NUMBER 65537 :: a Fermat prime, useful enough to become famous in RSA stories.",
    ]

    primes = [n for n in range(2, 30000) if _is_prime(n)]
    for p in primes[:260]:
        lines.append(
            f"PRIME WATCH :: {p} is prime; trial divisors only need to reach {math.isqrt(p)}.")

    twin_count = 0
    for p in primes:
        if _is_prime(p + 2):
            lines.append(f"TWIN PRIMES :: {p} and {p + 2} stand two steps apart.")
            twin_count += 1
            if twin_count >= 170:
                break

    safe_count = 0
    for p in primes:
        q = (p - 1) // 2
        if p > 5 and (p - 1) % 2 == 0 and _is_prime(q):
            lines.append(f"SAFE PRIME :: {p} is safe because ({p}-1)/2 = {q} is prime.")
            safe_count += 1
            if safe_count >= 150:
                break

    sophie_count = 0
    for p in primes:
        q = 2 * p + 1
        if _is_prime(q):
            lines.append(f"SOPHIE GERMAIN :: {p} is prime and 2*{p}+1 = {q} is prime.")
            sophie_count += 1
            if sophie_count >= 150:
                break

    emirp_count = 0
    for p in primes:
        r = int(str(p)[::-1])
        if r != p and _is_prime(r):
            lines.append(f"MIRROR PRIME :: {p} reverses to {r}, and both are prime.")
            emirp_count += 1
            if emirp_count >= 130:
                break

    for k in range(2, 180):
        n = k * (k + 1) // 2
        lines.append(f"TRIANGLE {n} :: 1+...+{k} stacks into a triangular number.")

    for k in range(2, 150):
        n = k * k
        lines.append(f"SQUARE {n} :: a {k} by {k} grid lands exactly on {n}.")

    for k in range(2, 70):
        n = k ** 3
        lines.append(f"CUBE {n} :: {k}^3 is a box of {n} unit cubes.")

    fibs = _fib_numbers(10_000_000)
    for i in range(4, min(len(fibs), 38)):
        lines.append(
            f"FIBONACCI {fibs[i]} :: {fibs[i - 1]} + {fibs[i - 2]} makes it appear.")

    for p in (2, 3, 5, 7, 13, 17, 19, 31):
        n = 2 ** p - 1
        if _is_prime(n):
            lines.append(f"MERSENNE PRIME :: 2^{p}-1 = {n} is prime.")

    for n in range(2, 900):
        s = _proper_divisor_sum(n)
        if s > n:
            lines.append(f"ABUNDANT {n} :: proper divisors sum to {s}, exceeding it by {s - n}.")
        if len(lines) >= target + 220:
            break

    semi_count = 0
    for n in range(4, 3000):
        factors = _prime_factors(n)
        if len(factors) == 2:
            lines.append(f"SEMIPRIME {n} :: it factors as {factors[0]} * {factors[1]}.")
            semi_count += 1
            if semi_count >= 120:
                break

    kap_count = 0
    for n in range(2, 10000):
        ok, left, right = _is_kaprekar(n)
        if ok:
            lines.append(f"KAPREKAR {n} :: {n}^2 splits as {left}+{right}.")
            kap_count += 1
            if kap_count >= 35:
                break

    narc_count = 0
    for n in range(10, 200000):
        if _is_narcissistic(n):
            lines.append(f"NARCISSISTIC {n} :: digit powers rebuild the number exactly.")
            narc_count += 1
            if narc_count >= 20:
                break

    happy_count = 0
    for n in range(2, 1000):
        if _is_happy(n):
            lines.append(f"HAPPY {n} :: repeated digit-square sums eventually reach 1.")
            happy_count += 1
            if happy_count >= 90:
                break

    amicable_pairs = [
        (220, 284), (1184, 1210), (2620, 2924), (5020, 5564),
        (6232, 6368), (10744, 10856), (12285, 14595),
        (17296, 18416), (63020, 76084), (66928, 66992),
    ]
    for a, b in amicable_pairs:
        if _proper_divisor_sum(a) == b and _proper_divisor_sum(b) == a:
            lines.append(f"AMICABLE PAIR :: {a} and {b} send divisor sums to each other.")

    lines = _dedupe(lines)
    if len(lines) < target:
        for n in range(2, 10000):
            lines.append(f"MOD FACT :: {n} leaves remainder {n % 9} modulo 9.")
            if len(_dedupe(lines)) >= target:
                break
        lines = _dedupe(lines)
    return lines[:target]


def _duration_text(seconds: float) -> str:
    seconds = float(seconds)
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.1f} sec"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} min"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.1f} hours"
    days = hours / 24
    if days < 730:
        return f"{days:.1f} days"
    years = days / 365.2425
    if years < 1_000_000:
        return f"{years:,.0f} years"
    return f"{years:.2e} years"


def _rate_text(rate: int) -> str:
    if rate >= 1_000_000_000_000:
        return f"{rate // 1_000_000_000_000}T/s"
    if rate >= 1_000_000_000:
        return f"{rate // 1_000_000_000}B/s"
    if rate >= 1_000_000:
        return f"{rate // 1_000_000}M/s"
    if rate >= 1_000:
        return f"{rate // 1_000}K/s"
    return f"{rate}/s"


def _bytes_text(n: float) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    value = float(n)
    unit = 0
    while value >= 1024 and unit < len(units) - 1:
        value /= 1024
        unit += 1
    if value >= 100:
        return f"{value:.0f} {units[unit]}"
    if value >= 10:
        return f"{value:.1f} {units[unit]}"
    return f"{value:.2f} {units[unit]}"


def build_computer_lines(target: int = TECH_TARGET) -> list[str]:
    lines = [
        "COMPUTE TIME :: Pentium 75 ran at 75 MHz; Ryzen 5 9600X boosts up to 5.4 GHz, a 72x clock ratio before cores and IPC.",
        "COMPUTE NOTE :: 72x clock ratio is not the whole speedup; cores, IPC, SIMD, cache, and memory join the party.",
        "CPU HISTORY :: Pentium 75 was already superscalar; the mid-1990s were not asleep.",
        "CPU SPEC :: Ryzen 5 9600X brings 6 cores, 12 threads, and a 32 MB L3 cache to the tiny status board.",
        "CACHE TRIP :: L1 is the desk, RAM is the hallway, SSD is another building; distance matters.",
        "QUANTUM NOTE :: Grover changes N brute-force checks into about sqrt(N) ideal oracle checks, not instant magic.",
        "PASSWORD NOTE :: 10^10 candidates is a search space, not a 10^10-digit password; wording matters.",
        "SECURITY NOTE :: rate limits beat heroic math when the attacker must ask the login form politely.",
        "HASH NOTE :: a salt does not hide a password; it stops easy reuse of precomputed tables.",
        "BACKUP NOTE :: RAID is uptime; backup is the part where future-you stops glaring.",
        "FLOAT NOTE :: 0.1 is not exactly 0.1 in binary floating point; the decimal is wearing a costume.",
        "NAN NOTE :: NaN is not equal to itself, which is rude but useful.",
        "UNIX TIME :: signed 32-bit Unix time reaches its cliff on 2038-01-19 at 03:14:08 UTC.",
        "IPv4 NOTE :: 2^32 is 4,294,967,296 addresses; the internet called that 'not enough'.",
        "IPv6 NOTE :: 2^128 is about 3.4e38 addresses; the address book got cosmic.",
        "ASCII NOTE :: 'A' is 65 decimal, 0x41 hex, and still looks confident.",
        "BYTE NOTE :: one byte is eight bits; tiny committee, large consequences.",
        "KIB NOTE :: 1 KiB is 1024 bytes; 1 KB is often 1000 bytes. Storage marketing noticed.",
    ]

    search_spaces = [
        ("4-digit PIN", 10 ** 4),
        ("6-digit code", 10 ** 6),
        ("8-digit code", 10 ** 8),
        ("10-digit numeric code", 10 ** 10),
        ("8 lowercase letters", 26 ** 8),
        ("10 lowercase letters", 26 ** 10),
        ("8 base62 chars", 62 ** 8),
        ("10 base62 chars", 62 ** 10),
        ("12 base62 chars", 62 ** 12),
        ("16 hex chars", 16 ** 16),
    ]
    rates = [1_000, 1_000_000, 1_000_000_000, 1_000_000_000_000]
    for label, space in search_spaces:
        for rate in rates:
            lines.append(
                f"BRUTE FORCE :: {label} has {space:,} candidates; at {_rate_text(rate)}, a full sweep is {_duration_text(space / rate)}.")
        root = math.isqrt(space)
        lines.append(
            f"GROVER SKETCH :: {label} has sqrt-space near {root:,} ideal oracle steps; reality still needs hardware and an oracle.")

    frames = [
        ("320x200 RGB frame", 320, 200, 3),
        ("640x480 RGB frame", 640, 480, 3),
        ("1920x1080 RGB frame", 1920, 1080, 3),
        ("3840x2160 RGB frame", 3840, 2160, 3),
        ("7680x4320 RGB frame", 7680, 4320, 3),
    ]
    for label, w, h, bpp in frames:
        size = w * h * bpp
        lines.append(f"PIXEL MATH :: one raw {label} is {_bytes_text(size)} before compression gets clever.")
        lines.append(f"VIDEO FIREHOSE :: {label} at 60 fps is {_bytes_text(size * 60)} per second raw.")

    bandwidths = [
        ("10 Mbit/s Ethernet", 10_000_000),
        ("100 Mbit/s Ethernet", 100_000_000),
        ("1 Gbit/s Ethernet", 1_000_000_000),
        ("10 Gbit/s Ethernet", 10_000_000_000),
        ("40 Gbit/s link", 40_000_000_000),
        ("100 Gbit/s link", 100_000_000_000),
    ]
    for label, bps in bandwidths:
        lines.append(f"NETWORK RAW :: {label} is {bps / 8 / 1_000_000:,.1f} MB/s before protocol overhead.")

    fiber_speed_km_s = 200_000
    for km in (1, 10, 100, 1000, 5000, 10000):
        ms = km / fiber_speed_km_s * 1000
        lines.append(f"LATENCY :: {km:,} km through fiber is roughly {ms:.2f} ms one-way before routers and queues.")
    lines.append("MOON PING :: light takes about 1.28 seconds Earth-to-Moon one-way; gaming there needs patience.")

    powers = [
        ("8-bit unsigned max", 2 ** 8 - 1),
        ("16-bit unsigned max", 2 ** 16 - 1),
        ("32-bit signed max", 2 ** 31 - 1),
        ("32-bit unsigned max", 2 ** 32 - 1),
        ("48-bit MAC space", 2 ** 48),
        ("64-bit unsigned max", 2 ** 64 - 1),
    ]
    for label, value in powers:
        lines.append(f"BIT LEDGER :: {label} is {value:,}.")

    caches = [
        ("L1 cache", "nanoseconds", "keeps hot data close enough to feel local"),
        ("L2 cache", "a few more nanoseconds", "is the slightly larger desk drawer"),
        ("L3 cache", "shared fast memory", "is the office pantry for cores"),
        ("RAM", "tens of nanoseconds", "is fast until cache has spoiled you"),
        ("NVMe SSD", "microseconds", "is a rocket compared with disks and slow compared with RAM"),
        ("hard disk seek", "milliseconds", "is geological time to a CPU"),
    ]
    for name, latency, joke in caches:
        lines.append(f"MEMORY LADDER :: {name} lives around {latency}; {joke}.")

    protocols = [
        ("TCP", "keeps order and retransmits lost pieces"),
        ("UDP", "sends and does not wait for applause"),
        ("DNS", "turns names into addresses so humans can remain decorative"),
        ("TLS", "wraps the conversation before the network hears gossip"),
        ("NTP", "keeps clocks from drifting into small fiction"),
        ("SSH", "puts a shell behind a locked door"),
        ("HTTP 404", "means the server answered but the thing was not there"),
        ("HTTP 500", "means the server had a difficult internal moment"),
    ]
    for name, fact in protocols:
        lines.append(f"PROTOCOL RADIO :: {name} {fact}.")

    old_new_pairs = [
        ("floppy disk", "1.44 MB", "one modern photo can casually ignore it"),
        ("CD-ROM", "650-700 MB", "once felt like a small universe"),
        ("DVD", "4.7 GB", "was a couch-sized movie shelf in a shiny circle"),
        ("Blu-ray", "25 GB single-layer", "made backups feel cinematic"),
        ("1 TB SSD", "about 931 GiB", "because decimal and binary units shake hands awkwardly"),
    ]
    for name, size, note in old_new_pairs:
        lines.append(f"STORAGE MUSEUM :: {name} held {size}; {note}.")

    cpu_generations = [
        ("8086", 1978, "16-bit x86 begins the long family story"),
        ("80386", 1985, "32-bit protected mode walks on stage"),
        ("Pentium", 1993, "superscalar x86 becomes a household word"),
        ("Athlon 64", 2003, "x86-64 arrives on the desktop"),
        ("Ryzen", 2017, "chiplets and many cores make the comeback loud"),
        ("Zen 5", 2024, "modern desktop cores keep the lineage moving"),
    ]
    for name, year, fact in cpu_generations:
        lines.append(f"CPU TIMELINE :: {name} in {year}: {fact}.")

    bit_counts = range(10, 80)
    for bits in bit_counts:
        values = 2 ** bits
        lines.append(f"BIT FACT :: {bits} bits can name {values:,} states.")
        if len(lines) >= target:
            return _dedupe(lines)[:target]

    adjectives = [
        "patient", "dramatic", "suspiciously fast", "retro", "well-cached",
        "packet-shaped", "bit-aligned", "latency-aware", "checksum-approved",
        "branch-predicted",
    ]
    nouns = [
        "CPU", "cache line", "packet", "thread", "register", "interrupt",
        "kernel", "socket", "hash", "frame buffer", "bootloader", "scheduler",
    ]
    facts = [
        "would like fewer round trips",
        "prefers locality over wandering",
        "knows that waiting is also work",
        "believes powers of two are furniture",
        "keeps a small table of recent decisions",
        "does not trust a single backup",
        "thinks compression is a magic trick with accounting",
        "wants the hot path to stay hot",
        "knows the fastest byte is the one never moved",
        "has opinions about clock drift",
    ]
    for adj in adjectives:
        for noun in nouns:
            for fact in facts:
                lines.append(f"COMPUTER RADIO :: the {adj} {noun} {fact}.")
                if len(_dedupe(lines)) >= target:
                    return _dedupe(lines)[:target]
    return _dedupe(lines)[:target]


def build_board_lines(target: int = BOARD_TARGET) -> list[str]:
    lines = [
        "RCM RADIO :: broadcasting low-resolution confidence since v1.5.",
        "BOARD NOTE :: the table does the work; this rectangle handles the atmosphere.",
        "PIXEL UNION :: letters reserve the right to move from right to left.",
        "NIGHT SHIFT :: yellow pixels have clocked in and look almost professional.",
        "FAKE MAINT :: polishing the diagnostic glow with a very small cloth.",
        "PUBLIC NOTICE :: text alignment incident resolved without a committee.",
        "ON AIR :: today's program is mostly ports, patience, and tiny arithmetic.",
        "BOARD HEALTH :: pixels awake, dignity variable, usefulness surprisingly high.",
        "INTERNAL MEMO :: every warning has been asked to use its indoor voice.",
        "SIGNAL CHECK :: suspiciously useful vibes detected on the black rectangle.",
    ]
    prefixes = [
        "RCM RADIO", "BOARD NOTE", "PIXEL UNION", "NIGHT SHIFT", "FAKE MAINT",
        "ON AIR", "PUBLIC NOTICE", "CONTROL ROOM", "DISPLAY OPS", "TEXT DEPOT",
        "STATUS THEATER", "TINY MEMO", "RETRO DESK", "SIGNAL CHECK", "SHIFT LOG",
        "LOCAL BROADCAST", "MINI BULLETIN", "OFFICIAL NONSENSE", "CALM ALERT",
        "WINDOW NOTE",
    ]
    subjects = [
        "yellow letters", "diagnostic pixels", "scrolling text fragments",
        "black-rectangle pixels", "tiny operators", "message-queue pixels",
        "today's confidence pixels", "cursor pixels", "status lamps",
        "left-margin pixels", "right-edge pixels", "scroll-belt pixels",
        "official-looking lines", "control-panel pixels", "small-broadcast pixels",
        "text-depot pixels", "window-chrome pixels", "idle pixels",
        "tiny-stage pixels", "maintenance-sign pixels",
    ]
    verbs = [
        "are rehearsing a useful sentence", "have requested better lighting",
        "are moving at a responsible speed", "are pretending this is mission control",
        "are checking their alignment", "have formed a temporary committee",
        "are carrying today's vibe report", "are waiting for a dramatic reason",
        "are polishing the warning label", "are measuring the silence",
        "are filing a calmness report", "are tuning the retro frequency",
        "are auditing the empty spaces", "are keeping the rectangle interesting",
        "are quietly overqualified", "are refreshing their tiny credentials",
        "are practicing a clean exit", "are testing low-resolution charisma",
        "are maintaining acceptable seriousness", "are giving the table some privacy",
    ]
    endings = [
        "please continue scrolling", "no meeting was required", "this is very official",
        "the margin approved", "the pixels deny everything", "confidence remains amber",
        "a tiny stamp has been applied", "all fonts remain accounted for",
        "the night desk concurs", "the rectangle feels seen", "no extra toolbar needed",
        "the vibe check passed", "the paperwork is decorative",
        "an unnecessary siren was not used", "the old UI nods politely",
        "the message will now drift away", "the glow is within tolerance",
        "the tiny stage is ready", "the scroll belt resumes", "the panel remains calm",
    ]
    for prefix in prefixes:
        for subject in subjects:
            for verb in verbs:
                ending = endings[(len(lines) + len(prefix) + len(subject)) % len(endings)]
                lines.append(f"{prefix} :: {subject} {verb}; {ending}.")
                if len(lines) >= target + 120:
                    return _dedupe(lines)[:target]
    return _dedupe(lines)[:target]


def _sprite(frames, caption, color="#d0a000", accent="#40c0ff"):
    return frames, caption, color, accent


def _base_sprite_specs():
    return [
        _sprite(((("  ~~  ", " [__] ", "  ||  "), (" ~~ ~ ", " [__] ", "  ||  "))),
                "coffee pixels reporting for night shift"),
        _sprite(((("  ))  ", "  ||  ", " /__\\ "), ("  ))) ", "  ||  ", " /__\\ "))),
                "antenna receiving unnecessary confidence"),
        _sprite((((" ____ ", "|_[]_|", " o  o "), (" ____ ", "|_[]_|", "  o  o"))),
                "tiny cart delivering fresh diagnostics"),
        _sprite((((" .--. ", "|_[]|", " /__\\"), (" .--. ", "|_##|", " /__\\"))),
                "monitor practicing its important face"),
        _sprite(((("  __  ", " /||\\ ", "o_||_o"), ("  __  ", " /||\\ ", " o||o "))),
                "balance machine thinking about perfect numbers"),
        _sprite((((" |\\/| ", " |/\\| ", "  ||  "), (" |/\\| ", " |\\/| ", "  ||  "))),
                "mirror checking whether primes still look prime"),
        _sprite(((("[]-[]-", "  []  ", "-[]-[]"), ("-[]-[]", "  []  ", "[]-[]-"))),
                "perfect-number parade passing the platform"),
        _sprite((((" [ON] ", " /||\\ ", "  ||  "), (" [AI] ", " /||\\ ", "  ||  "))),
                "RCM radio is briefly on air"),
        _sprite(((("  /|  ", " /_|  ", "  ||  "), (" |\\   ", " |_\\  ", "  ||  "))),
                "pixel broom sweeping unused drama"),
        _sprite((((" o/   ", "/|    ", "/ \\   "), (" \\o   ", "  |\\  ", " / \\  "))),
                "tiny operator repainting yellow letters"),
        _sprite(((("  _   ", " / \\  ", " \\_/  "), ("      ", " /_\\  ", " \\_/  "))),
                "moon-shaped idle mode keeping watch"),
        _sprite((((" .__. ", "|_  | ", "|___| "), (" .__. ", "|__ | ", "|___| "))),
                "safe-prime vault locked twice"),
        _sprite(((("  __  ", " /_o\\ ", "  /\\  "), ("  __  ", " /o_\\ ", "  /\\  "))),
                "small telescope searching for the next prime"),
        _sprite((((" .--. ", "|123|", "|+==|"), (" .--. ", "|752|", "|3==|"))),
                "calculator whispering about 7523"),
        _sprite(((("o-o-o ", " | |  ", "o-o-o "), (" o-o-o", "  | | ", " o-o-o"))),
                "abacus sliding through the control room"),
        _sprite((((" > >  ", "  > > ", " > >  "), ("  > > ", " > >  ", "  > > "))),
                "signal arrows commuting across the sign"),
        _sprite(((("  *   ", " ***  ", "  *   "), (" ***  ", "***** ", " ***  "))),
                "sparkle budget approved for one second"),
        _sprite((((" [=]  ", "/___\\ ", " | |  "), (" [#]  ", "/___\\ ", " | |  "))),
                "tiny lab testing whether the rectangle is awake"),
        _sprite((((" [ ]  ", " | |  ", " |_|  "), (" [_]  ", " | |  ", " |_|  "))),
                "elevator for small ideas between lines two and three"),
        _sprite(((("====> ", "====  ", "==    "), ("  ===>", "  ==== ", "    =="))),
                "conveyor belt transporting official nonsense"),
        _sprite((((" |\\   ", " |#\\  ", " |    "), (" |/   ", " |#\\  ", " |    "))),
                "tiny flag marking a solved alignment dispute"),
        _sprite(((("[____]", "|_||_|", "  ||  "), ("[####]", "|_||_|", "  ||  "))),
                "keyboard pretending it has more keys"),
        _sprite((((" \\ /  ", "  X   ", " / \\  "), (" / \\  ", "  X   ", " \\ /  "))),
                "hourglass spending time responsibly"),
        _sprite(((("  ()  ", " /||  ", "  ||  "), ("  ( ) ", " /||  ", "  ||  "))),
                "lens inspecting suspiciously round numbers"),
        _sprite(((("  ||  ", " [##] ", " /__\\ "), ("  ||  ", " [--] ", " /__\\ "))),
                "tower blinking a calm status light"),
    ]


def build_pixel_scenes(target: int = SCENE_TARGET) -> list[PixelScene]:
    captions = [
        "math radio warming up the tiny tubes",
        "letters loading onto the scroll belt",
        "low-resolution seriousness detected",
        "today's rectangle has chosen curiosity",
    ]
    scenes = []
    specs = _base_sprite_specs()
    for idx, (frames, caption, color, accent) in enumerate(specs):
        for variant, extra in enumerate(captions):
            final_caption = caption if variant == 0 else extra
            scenes.append(PixelScene(
                key=f"scene_{idx:02d}_{variant}",
                frames=tuple(tuple(row for row in frame) for frame in frames),
                caption=final_caption,
                color=color,
                accent=accent,
            ))
            if len(scenes) >= target:
                return scenes
    return scenes


class _ShuffleDeck:
    def __init__(self, items, rng: random.Random):
        self._items = list(items)
        self._rng = rng
        self._deck = []
        self._last = None

    def next(self):
        if not self._deck:
            self._deck = list(self._items)
            self._rng.shuffle(self._deck)
            if len(self._deck) > 1 and self._deck[-1] == self._last:
                self._deck[0], self._deck[-1] = self._deck[-1], self._deck[0]
        self._last = self._deck.pop()
        return self._last


class BoardFeed:
    def __init__(self, seed: str = ""):
        digest = hashlib.sha256(str(seed or "rcm-status-board").encode("utf-8")).hexdigest()
        seed_int = int(digest[:16], 16)
        self._rng = random.Random(seed_int)
        self.math_lines = build_math_lines()
        self.tech_lines = build_computer_lines()
        self.board_lines = build_board_lines()
        self.pixel_scenes = build_pixel_scenes()
        self._math_deck = _ShuffleDeck(self.math_lines, self._rng)
        self._tech_deck = _ShuffleDeck(self.tech_lines, self._rng)
        self._board_deck = _ShuffleDeck(self.board_lines, self._rng)
        self._scene_deck = _ShuffleDeck(self.pixel_scenes, self._rng)
        self._kind_deck = _ShuffleDeck(
            ["math", "math", "tech", "tech", "tech", "board", "board", "board"],
            self._rng,
        )

    @property
    def counts(self) -> tuple[int, int, int, int]:
        return (
            len(self.math_lines),
            len(self.tech_lines),
            len(self.board_lines),
            len(self.pixel_scenes),
        )

    def next_line(self) -> str:
        kind = self._kind_deck.next()
        if kind == "math":
            return self._math_deck.next()
        if kind == "tech":
            return self._tech_deck.next()
        return self._board_deck.next()

    def next_scene(self) -> PixelScene:
        return self._scene_deck.next()
