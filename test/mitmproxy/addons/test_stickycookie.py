import pytest

from mitmproxy.addons import stickycookie
from mitmproxy.test import taddons
from mitmproxy.test import tflow
from mitmproxy.test import tutils as ntutils


def test_domain_match():
    assert stickycookie.domain_match("www.google.com", ".google.com")
    assert stickycookie.domain_match("google.com", ".google.com")


class TestStickyCookie:
    def test_config(self):
        sc = stickycookie.StickyCookie()
        with taddons.context(sc) as tctx:
            with pytest.raises(Exception, match="Invalid filter expression"):
                tctx.configure(sc, stickycookie="~b")

            tctx.configure(sc, stickycookie="foo")
            assert sc.flt
            tctx.configure(sc, stickycookie=None)
            assert not sc.flt

    def test_simple(self):
        sc = stickycookie.StickyCookie()
        with taddons.context(sc) as tctx:
            tctx.configure(sc, stickycookie=".*")
            f = tflow.tflow(resp=True)
            f.response.headers["set-cookie"] = "foo=bar"
            sc.request(f)

            sc.response(f)

            assert sc.jar
            assert "cookie" not in f.request.headers

            f = f.copy()
            sc.request(f)
            assert f.request.headers["cookie"] == "foo=bar"

    def _response(self, sc, cookie, host):
        f = tflow.tflow(req=ntutils.treq(host=host, port=80), resp=True)
        f.response.headers["Set-Cookie"] = cookie
        sc.response(f)
        return f

    def test_response(self):
        sc = stickycookie.StickyCookie()
        with taddons.context(sc) as tctx:
            tctx.configure(sc, stickycookie=".*")

            c = (
                "SSID=mooo; domain=.google.com, FOO=bar; Domain=.google.com; Path=/; "
                "Expires=Wed, 13-Jan-2021 22:23:01 GMT; Secure; "
            )

            self._response(sc, c, "host")
            assert not sc.jar.keys()

            self._response(sc, c, "www.google.com")
            assert sc.jar.keys()

            sc.jar.clear()
            self._response(sc, "SSID=mooo", "www.google.com")
            assert list(sc.jar.keys())[0] == ("www.google.com", 80, "/")

    def test_response_multiple(self):
        sc = stickycookie.StickyCookie()
        with taddons.context(sc) as tctx:
            tctx.configure(sc, stickycookie=".*")

            # Test setting of multiple cookies
            c1 = "somecookie=test; Path=/"
            c2 = "othercookie=helloworld; Path=/"
            f = self._response(sc, c1, "www.google.com")
            f.response.headers["Set-Cookie"] = c2
            sc.response(f)
            googlekey = list(sc.jar.keys())[0]
            assert len(sc.jar[googlekey].keys()) == 2

    def test_response_weird(self):
        sc = stickycookie.StickyCookie()
        with taddons.context(sc) as tctx:
            tctx.configure(sc, stickycookie=".*")

            # Test setting of weird cookie keys
            f = tflow.tflow(req=ntutils.treq(host="www.google.com", port=80), resp=True)
            cs = [
                "foo/bar=hello",
                "foo:bar=world",
                "foo@bar=fizz",
            ]
            for c in cs:
                f.response.headers["Set-Cookie"] = c
                sc.response(f)
            googlekey = list(sc.jar.keys())[0]
            assert len(sc.jar[googlekey].keys()) == len(cs)

    def test_response_overwrite(self):
        sc = stickycookie.StickyCookie()
        with taddons.context(sc) as tctx:
            tctx.configure(sc, stickycookie=".*")

            # Test overwriting of a cookie value
            c1 = "somecookie=helloworld; Path=/"
            c2 = "somecookie=newvalue; Path=/"
            f = self._response(sc, c1, "www.google.com")
            f.response.headers["Set-Cookie"] = c2
            sc.response(f)
            googlekey = list(sc.jar.keys())[0]
            assert len(sc.jar[googlekey]) == 1
            assert sc.jar[googlekey]["somecookie"] == "newvalue"

    def test_response_delete(self):
        sc = stickycookie.StickyCookie()
        with taddons.context(sc) as tctx:
            tctx.configure(sc, stickycookie=".*")

            # Test that a cookie is be deleted
            # by setting the expire time in the past
            f = self._response(sc, "duffer=zafar; Path=/", "www.google.com")
            f.response.headers["Set-Cookie"] = (
                "duffer=; Expires=Thu, 01-Jan-1970 00:00:00 GMT"
            )
            sc.response(f)
            assert not sc.jar.keys()

    def test_request(self):
        sc = stickycookie.StickyCookie()
        with taddons.context(sc) as tctx:
            tctx.configure(sc, stickycookie=".*")

            f = self._response(sc, "SSID=mooo", "www.google.com")
            assert "cookie" not in f.request.headers
            sc.request(f)
            assert "cookie" in f.request.headers


# RFC 6265, Section 5.1.4: a request-path path-matches a cookie-path if both are
# identical, or if the cookie-path is a prefix and the cookie-path ends in "/" or the
# request-path continues with "/". The query string is not part of the request-path.
STICKY_COOKIE_PATH_CASES = [
    # exact match and children
    ("/app", "/app", True),
    ("/app", "/app/child", True),
    # prefix without a path boundary is not a match
    ("/app", "/application", False),
    ("/app", "/app-v2", False),
    # query string is ignored
    ("/app", "/app?view=1", True),
    ("/app", "/app/?view=1", True),
    ("/app", "/app?next=/app/child", True),
    ("/app", "/appx?next=/app/child", False),
    # the request query is stripped before matching, so a cookie path that itself
    # contains "?" cannot match that same target
    ("/app?view=1", "/app?view=1", False),
    # trailing slash in the cookie path requires that slash
    ("/app/", "/app", False),
    ("/app/", "/app/", True),
    ("/app/", "/app/child", True),
    # root matches everything, unrelated paths do not
    ("/", "/unrelated", True),
    ("/app", "/other", False),
    # paths are case-sensitive
    ("/app", "/APP", False),
    ("/app", "/App/child", False),
    # escaped separators are not decoded
    ("/app", "/app%2Fchild", False),
    ("/app/x", "/app%2Fx", False),
]


def _request(request_path: str, host: str = "example.invalid", port: int = 80):
    return ntutils.treq(host=host, port=port, path=request_path.encode())


def _seed_cookie(
    sc: stickycookie.StickyCookie,
    cookie_path: str,
    host: str = "example.invalid",
    port: int = 80,
) -> None:
    f = tflow.tflow(req=_request("/app/index", host=host, port=port), resp=True)
    f.response.headers["Set-Cookie"] = f"fixture=synthetic; Path={cookie_path}"
    sc.response(f)


def _cookie_attached(
    sc: stickycookie.StickyCookie,
    request_path: str,
    host: str = "example.invalid",
    port: int = 80,
) -> bool:
    f = tflow.tflow(req=_request(request_path, host=host, port=port))
    sc.request(f)
    return f.request.headers.get("cookie") == "fixture=synthetic"


@pytest.mark.parametrize("cookie_path,request_path,attached", STICKY_COOKIE_PATH_CASES)
def test_path_match(cookie_path: str, request_path: str, attached: bool):
    sc = stickycookie.StickyCookie()
    with taddons.context(sc) as tctx:
        tctx.configure(sc, stickycookie=".*")
        _seed_cookie(sc, cookie_path)
        assert list(sc.jar) == [("example.invalid", 80, cookie_path)]
        assert _cookie_attached(sc, request_path) is attached


def test_path_match_host_port_scope():
    sc = stickycookie.StickyCookie()
    with taddons.context(sc) as tctx:
        tctx.configure(sc, stickycookie=".*")
        _seed_cookie(sc, "/app")
        assert list(sc.jar) == [("example.invalid", 80, "/app")]
        assert _cookie_attached(sc, "/app")
        assert not _cookie_attached(sc, "/app", host="other.invalid")
        assert not _cookie_attached(sc, "/app", port=8080)
