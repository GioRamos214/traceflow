class Cart:
    def __init__(self, catalog):
        self.catalog = catalog
        self.items = []

    def add(self, sku):
        if sku not in self.catalog:
            raise KeyError(sku)
        self.items.append(sku)

    def total(self):
        return sum(self.catalog[sku] for sku in self.items)
