DISCOUNTS = {"SAVE10": 0.10, "HALF": 0.50}


def apply_discount(amount, code):
    if code is None:
        return amount
    rate = DISCOUNTS.get(code.upper(), 0)
    return round(amount * (1 - rate), 2)
