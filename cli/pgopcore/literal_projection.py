"""Bounded literal projection over bytes already checked by acquisition."""

from bisect import bisect_right


def comparable(raw, ignore_case):
    return raw.lower() if ignore_case else raw


def occurrences(raw, needle, limit):
    """Return total count and an iterator over at most limit nonoverlapping spans."""
    count = raw.count(needle)

    def spans():
        end = 0
        for _ in range(min(count, limit)):
            start = raw.find(needle, end)
            end = start + len(needle)
            yield start, end

    return count, spans()


def citation(raw, breaks, start, end):
    return {"line_start": bisect_right(breaks, start) + 1,
            "line_end": bisect_right(breaks, end - 1) + 1,
            "byte_start": start, "byte_end": end, "excerpt": raw[start:end].decode("utf-8")}
