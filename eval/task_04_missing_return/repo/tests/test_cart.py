from src.cart import total_price


def test_single_item():
    assert total_price([{"price": 5.0, "qty": 3}]) == 15.0


def test_multiple_items():
    items = [{"price": 10, "qty": 2}, {"price": 3, "qty": 5}]
    assert total_price(items) == 35


def test_empty_cart():
    assert total_price([]) == 0
