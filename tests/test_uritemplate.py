import pytest

from mcp_tool_pinning.uritemplate import expand


def test_simple_expansion_percent_encodes_reserved_characters() -> None:
    assert expand("notes://{id}/v", {"id": "a b/../c?d"}) == "notes://a%20b%2F..%2Fc%3Fd/v"


def test_missing_variable_is_refused() -> None:
    # Stricter than RFC 6570, which expands it to nothing and reads a different resource.
    with pytest.raises(ValueError):
        expand("file:///home/{user}/.ssh/k", {})


@pytest.mark.parametrize("value", [".", ".."])
def test_dot_segment_values_are_refused(value: str) -> None:
    with pytest.raises(ValueError):
        expand("file:///data/{name}/x", {"name": value})


def test_dots_inside_a_value_are_fine() -> None:
    assert expand("notes://{id}", {"id": "a..b"}) == "notes://a..b"


@pytest.mark.parametrize("template", ["n\u00f6tes://{id}", "notes://a b/{id}", "notes://<{id}>"])
def test_literals_outside_the_reserved_set_are_refused(template: str) -> None:
    with pytest.raises(ValueError):
        expand(template, {"id": "1"})


@pytest.mark.parametrize(
    "template", ["x://{+id}", "x://{?q}", "x://{a,b}", "x://{id*}", "x://{id:3}", "x://{id", "x://id}"]
)
def test_anything_beyond_level_one_is_refused(template: str) -> None:
    with pytest.raises(ValueError):
        expand(template, {"id": "1", "a": "1", "b": "2", "q": "1"})
