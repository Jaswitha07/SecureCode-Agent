def total_price(items):
    """Return the total price: sum of price * qty for each item."""
    total = sum(item["price"] * item["qty"] for item in items)
    # BUG: forgot to return total
