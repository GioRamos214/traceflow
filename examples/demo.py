"""A self-contained demo for screenshots — no input needed.

    traceflow run examples/demo.py

It exercises every panel of the viewer: a multi-level call tree, if/elif/else and
loop branches, an exception that's raised and caught, and program output attributed
to the call that produced it.
"""

import time

INVENTORY = {"widget": 4, "gadget": 0, "gizmo": 12}
PRICES = {"widget": 2.50, "gadget": 9.99, "gizmo": 1.25}


class OutOfStock(Exception):
    pass


def price_of(item, qty):
    unit = PRICES[item]
    if qty >= 10:
        tier = "bulk (10% off)"
        factor = 0.90
    elif qty >= 3:
        tier = "small discount"
        factor = 0.97
    else:
        tier = "standard"
        factor = 1.0
    print(f"    pricing {item}: {tier}")
    return round(unit * qty * factor, 2)


def reserve(item, qty):
    have = INVENTORY.get(item, 0)
    if have < qty:
        raise OutOfStock(f"{item}: wanted {qty}, have {have}")
    INVENTORY[item] = have - qty
    time.sleep(0.003)
    return price_of(item, qty)


def checkout(cart):
    total = 0.0
    for item, qty in cart.items():
        try:
            cost = reserve(item, qty)
            print(f"  {qty}x {item} -> ${cost:.2f}")
            total += cost
        except OutOfStock as e:
            print(f"  skipped {e}")
    return round(total, 2)


def main():
    print("Processing order...")
    cart = {"widget": 2, "gadget": 1, "gizmo": 10}
    total = checkout(cart)
    print(f"Order total: ${total:.2f}")


if __name__ == "__main__":
    main()
