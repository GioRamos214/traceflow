import sys

from .core.cart import Cart
from .core.pricing import apply_discount
from .storage.catalog import load_catalog


def main():
    code = sys.argv[1] if len(sys.argv) > 1 else None
    catalog = load_catalog()
    cart = Cart(catalog)
    for sku in ["apple", "pear", "dragonfruit"]:
        try:
            cart.add(sku)
        except KeyError as e:
            print(f"skipped {e}")
    total = apply_discount(cart.total(), code)
    print(f"Total: {total:.2f}")
