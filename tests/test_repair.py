from pydantic import BaseModel
from sentinel.jury.repair import JSONRepairHarness


class SimpleModel(BaseModel):
    name: str
    count: int


def test_repair_clean_json():
    raw = '{"name": "test", "count": 42}'
    parsed, err = JSONRepairHarness.parse_and_validate(raw, SimpleModel)
    assert err is None
    assert parsed.name == "test"
    assert parsed.count == 42


def test_repair_markdown_fences():
    raw = '```json\n{"name": "fenced", "count": 10}\n```'
    parsed, err = JSONRepairHarness.parse_and_validate(raw, SimpleModel)
    assert err is None
    assert parsed.name == "fenced"
    assert parsed.count == 10


def test_repair_trailing_commas():
    raw = '{"name": "trailing", "count": 5, }'
    parsed, err = JSONRepairHarness.parse_and_validate(raw, SimpleModel)
    assert err is None
    assert parsed.name == "trailing"
    assert parsed.count == 5


def test_repair_conversational_wrapping():
    raw = 'Here is your security audit result:\n\n{"name": "wrapped", "count": 99}\n\nHope this helps!'
    parsed, err = JSONRepairHarness.parse_and_validate(raw, SimpleModel)
    assert err is None
    assert parsed.name == "wrapped"
    assert parsed.count == 99
