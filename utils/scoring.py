# utils/scoring.py

def clamp(value: float, minimum: float, maximum: float) -> float:
    """
    Clamp a numeric value between minimum and maximum.

    Used to ensure severity scores stay within 0–10.
    """
    if value < minimum:
        return minimum
    if value > maximum:
        return maximum
    return value
