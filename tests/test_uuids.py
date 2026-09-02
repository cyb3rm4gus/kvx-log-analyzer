from loganalyzer.uuids import parse_uuids


def test_parse_tolerates_separators_and_case():
    p = parse_uuids("11111111-1111-4111-8111-111111111111, 22222222-2222-4222-8222-222222222222\n"
                    "'11111111-1111-4111-8111-111111111111'\nnot-a-uuid;\n")
    assert p.uuids == ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"]
    assert p.rejected == ["not-a-uuid"]
    assert p.duplicates == 1


def test_uppercase_is_normalised():
    p = parse_uuids("11111111-1111-4111-8111-AAAAAAAAAAAA")
    assert p.uuids == ["11111111-1111-4111-8111-aaaaaaaaaaaa"]


def test_truncates_past_max():
    from loganalyzer.uuids import MAX_UUIDS
    text = "\n".join(f"{i:08x}-1111-4111-8111-111111111111" for i in range(MAX_UUIDS + 5))
    p = parse_uuids(text)
    assert len(p.uuids) == MAX_UUIDS and p.truncated == 5


def test_empty():
    assert parse_uuids("   \n ").uuids == []
