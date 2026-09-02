import httpx
import pytest

from loganalyzer import guardhouse as gh
from tests.conftest import PII_EMAIL, PII_PHONE, U1, U_UNKNOWN, MockGuardhouse, ev, paged


def make(mock: MockGuardhouse) -> gh.GuardhouseClient:
    return gh.GuardhouseClient("http://gh.test", "tok", transport=mock.transport())


async def test_page_strips_pii_and_keeps_nine_columns():
    mock = MockGuardhouse({U1: paged([ev("2026-08-01 10:00:00")], 1000)})
    page = await make(mock).events_page(U1, 1)
    assert page.has_more is False and page.page == 1
    assert set(page.events[0]) == set(gh.EVENT_KEYS)
    assert PII_EMAIL not in repr(page) and PII_PHONE not in repr(page)


async def test_404_is_not_found():
    with pytest.raises(gh.NotFound):
        await make(MockGuardhouse()).events_page(U_UNKNOWN)


@pytest.mark.parametrize("status,code,exc", [
    (401, "unauthenticated", gh.AuthError), (403, "forbidden", gh.AuthError),
    (400, "invalid_param", gh.InvalidParam), (502, "upstream_failed", gh.Upstream),
    (504, "upstream_timeout", gh.Upstream), (500, "source_desync", gh.Desync),
    (500, "internal", gh.GuardhouseError),
])
async def test_error_mapping(status, code, exc):
    mock = MockGuardhouse()
    mock.script(U1, httpx.Response(status, json={"error": {"code": code, "message": "m", "request_id": "x"}}))
    with pytest.raises(exc) as ei:
        await make(mock).events_page(U1)
    assert ei.value.code == code


@pytest.mark.parametrize("status", [429, 503])
async def test_unavailable_carries_retry_after(status):
    mock = MockGuardhouse()
    mock.script(U1, httpx.Response(status, headers={"Retry-After": "7"},
                                   json={"error": {"code": "rate_limited", "message": "m", "request_id": "x"}}))
    with pytest.raises(gh.Unavailable) as ei:
        await make(mock).events_page(U1)
    assert ei.value.retry_after == 7.0


async def test_connection_error_is_the_analysts_vpn():
    mock = MockGuardhouse()
    mock.raise_connect = True
    with pytest.raises(gh.ConnectionLost):
        await make(mock).events_page(U1)
    assert await make(mock).ready() is False
