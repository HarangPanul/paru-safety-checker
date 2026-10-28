# 중간 표현(IR) 스키마 초안

> 상태: **초안(구현 전)**. 아직 코드에는 없고, 아래 "현재 출처" 열은 지금 있는 코드에서 채울 수 있는지를 적은 것입니다.

## 목적
PKGBUILD 한 묶음을 **한 번 파싱한 사실의 목록**으로 만들고, 거기서 세 가지 출력을 만듭니다.

```
파일들 ─ 전처리/파싱 ─▶ IR (사실 + 줄 번호 + 읽지 못한 구간) ─┬─▶ 사람용 요약
                                                              ├─▶ AI 입력 (원문과 함께)
                                                              └─▶ 규칙 (IR을 입력으로)
```
규칙, 사람용 출력, AI 입력이 서로 다른 해석을 하지 않게 하는 것이 핵심입니다.

## 원칙
1. **모든 항목에 근거 줄이 있다.** `file` + `line`(또는 `lines`) 없는 사실은 만들지 않습니다.
2. **모르는 것은 `unknown`으로 남긴다.** 추측으로 채우지 않습니다. 읽지 못한 구간은 `gaps`에 명시합니다.
3. **덮개 불변식(coverage).** 주석이 아닌 모든 줄은 `declarations`, `steps`, `gaps` 중 하나에 속합니다. 어디에도 없는 줄이 있으면 IR 생성이 실패한 것입니다(테스트로 검사).
4. **IR 안의 문자열은 모두 신뢰할 수 없는 데이터다.** `text`, `argv`, `url` 등은 PKGBUILD에서 온 값이므로, 렌더링할 때 구분자와 이스케이프로 감싸고 모델에는 데이터로만 전달합니다.
5. **판정을 담지 않는다.** IR은 사실이다. `marks`(규칙이 표시한 곳)는 IR 위에 별도 층으로 붙고, IR 본체와 섞이지 않습니다.
6. **원문은 항상 함께 간다.** IR은 원문의 요약 층이며 대체물이 아닙니다. 특히 `gaps` 구간은 원문 그대로 전달합니다.

## 스키마

```jsonc
{
  "ir_version": 1,
  "package": "foo",

  "files": [                               // 받은 모든 파일
    { "path": "PKGBUILD", "kind": "pkgbuild|install|patch|script|data|binary|symlink|omitted",
      "bytes": 1234, "truncated": false,
      "parse": "ok|failed|not-shell" }     // failed면 아래 gaps에 전체 범위가 들어간다
  ],

  "declarations": {                        // 변수와 배열 (코드가 아니라 선언)
    "pkgname": {"value": ["foo"], "line": 1},
    "pkgver":  {"value": "1.2.3", "line": 2},
    "arch":    {"value": ["x86_64"], "line": 4},
    "license": {"value": ["MIT"], "line": 5}
    // 그 밖의 literal 변수는 variables에, 값이 확정되지 않으면 "unresolved": true
  },

  "sources": [                             // source / source_<arch> 항목
    { "id": "src1", "url": "https://example.com/foo-1.2.3.tar.gz", "scheme": "https",
      "vcs": null,                         // git|svn|hg|bzr 이면 종류
      "pinned": true,                      // 내용이 고정되는가 (체크섬 또는 #commit/#tag)
      "checksum": "set|SKIP|none",
      "line": 8, "overridden": false }     // 뒤에서 덮어써진 선언도 남긴다
  ],

  "dependencies": [
    { "name": "glibc", "kind": "depends|makedepends|checkdepends|optdepends",
      "constraint": ">=2.30", "in_official_repo": true, "line": 10 }   // null 허용(조회 안 함)
  ],

  "units": [                               // 코드가 놓인 단위: 함수, 최상위, 설치 훅
    { "id": "build", "kind": "function|toplevel|hook",
      "file": "PKGBUILD", "lines": [14, 22],
      "runs": "as-user|as-root-on-install|at-parse",   // 누가, 언제 실행하는가
      "steps": ["s1", "s2", "s3"] }
  ],

  "steps": [                               // 명령 하나 = 한 단계. 파이프라인은 stage로 이어진다
    { "id": "s2", "unit": "build", "file": "PKGBUILD", "line": 16,
      "text": "curl -fsSL https://x/y.sh | sh",        // 한 줄로 푼 원본 (신뢰 불가)
      "program": "sh",                     // 래퍼를 벗긴 실제 프로그램
      "argv": ["-s"],
      "via": [],                           // ["sudo", "env"] 처럼 벗겨낸 래퍼
      "known": true,                       // 도구 번역표에 있는 프로그램인가
      "pipeline": { "stage": 2, "of": 2, "fed_by": ["s1"] },   // 이전 단계 id
      "ops": [                             // 이 단계가 하는 일 (아래 표)
        { "op": "exec", "target": "stdin", "from": "s1" }
      ],
      "inside": null }                     // "sh -c" / eval 문자열 안에서 나왔다면 바깥 단계 id
  ],

  "effects": {                             // steps에서 계산한 색인 (사람용 요약과 규칙이 쓴다)
    "network":  [{"step": "s1", "url": "https://x/y.sh", "scheme": "https"}],
    "writes":   [{"step": "s5", "path": "$pkgdir/usr/bin/foo", "area": "pkgdir"}],
    "deletes":  [],
    "reads":    [],
    "privilege":[{"step": "s9", "program": "sudo"}],
    "installs": [{"step": "s7", "via": "pacman|pip|npm|cargo|go|gem", "what": "..."}]
  },

  "gaps": [                                // 이 구간은 IR이 이해하지 못했다
    { "file": "PKGBUILD", "lines": [30, 31],
      "reason": "parse-failed|dynamic-command|unknown-program|truncated|binary|unreadable|overlong-line|inline-code|heredoc-body",
      "note": "command name is built at run time ($c)" }
  ],

  "marks": [                               // 규칙·허용 목록이 표시한 곳 (IR 위의 별도 층)
    { "rule": "pipe-to-shell", "severity": "danger", "step": "s2", "line": 16, "message": "..." }
  ]
}
```

### `ops`의 종류
| op | 필드 | 뜻 |
|---|---|---|
| `fetch` | `url`, `to`(파일 또는 stdout) | 네트워크에서 받음 |
| `exec` | `target`(path 또는 `stdin`), `from`(어느 단계가 먹여 주는지) | 프로그램/스크립트 실행 |
| `write` / `delete` / `read` | `path`, `area` | 파일 접근. `area`: `srcdir`, `pkgdir`, `home`, `system`, `tmp`, `device`, `unresolved` |
| `chmod` | `path`, `mode`, `sets_id_bit` | 권한 변경 |
| `install-pkg` | `via`, `what` | 패키지 매니저로 설치 |
| `decode` | `kind`(base64 등) | 디코드/압축 해제 |
| `spawn` | `detached` | 빌드 이후에도 남는 프로세스 |
| `other` | – | 번역표에 없음 → `known: false`이고 `gaps`에도 기록 |

## 현재 출처 (지금 코드에서 채울 수 있는가)
| IR 필드 | 현재 출처 | 상태 |
|---|---|---|
| `files`, `truncated` | `fetch.collect_files` | 있음 |
| `parse` / 파싱 실패 | `preprocess` + `crosscheck` | 있음 (줄 범위는 부분적) |
| `declarations`, `variables` | `ParsedFile.definitions`, `variables` | 있음 |
| `sources` | `heuristics.source_entries` | 있음 |
| `dependencies` | `heuristics.dependencies` | 부분 (종류 구분, `in_official_repo`는 CLI에서 따로) |
| `units` | `Line.region`, 함수 줄 | 부분 (함수 범위 기록 필요) |
| `steps.program/argv/via` | `strict.Command`, `invocation.views` | 있음 |
| `steps.pipeline` | `Command.segment/piped`, `ParsedCommand.upstream` | 있음 |
| `steps.inside` | `parsed._collect` (payload) | 부분 (바깥 단계 id 보존 필요) |
| `ops` (write/delete/read) | `fileaccess.file_accesses` | 있음 (근사) |
| `ops` (fetch/exec/decode) | `cmdrules.command_tags`, `fetch_then_execute` | 부분 (정리 필요) |
| `effects` | `activity.build_activity` | 있음 (자료구조 정리 필요) |
| `gaps` | `unparsed_lines`, `dynamic-command`, `overlong-line`, `_file_gap` | 흩어져 있음 → 한 곳으로 모으기 |
| `marks` | `heuristics.scan` 결과(`Finding`) | 있음 |

## 렌더링 (같은 IR에서 세 가지 출력)
- **사람용**: `sources`, `dependencies`, `units`별 한 줄 요약, `effects`, 맨 위에 `gaps`와 `marks`. 모든 줄에 `파일:줄`.
- **AI용**: 위 항목을 압축한 텍스트 + 원문(줄 번호 포함). 순서는 `gaps` → `marks` → `effects` → `sources`/`dependencies` → `units` → 원문. 일상적인 `$pkgdir` 작업은 개수와 줄 범위로 접고, `step id`는 유지해서 AI의 답이 근거를 가리키게 합니다.
- **도구용**: JSON 그대로. 코퍼스 측정과 테스트가 이를 읽습니다.

## 검사할 불변식 (테스트 후보)
1. 덮개: 주석이 아닌 모든 줄이 `declarations ∪ steps ∪ gaps`에 속한다.
2. 모든 `line`/`lines`가 해당 파일의 실제 범위 안에 있고, `steps.text`가 그 줄의 내용에서 나온다.
3. `fed_by`와 `from`은 같은 줄(그룹) 안의 실제 단계 id를 가리킨다.
4. `known: false`인 단계는 `gaps`에도 있다.
5. IR → 사람용 → 줄 번호로 원문 찾기가 항상 가능하다.
6. 같은 입력은 같은 IR을 만든다(결정적). 규칙의 결과는 IR만으로 재현된다.
7. 입력이 길어져도 생성 시간은 선형이다(앞서 찾은 이차 시간 문제 재발 방지).

## 열린 질문
- `units`를 함수 단위로만 둘지, `if`/`case` 분기까지 나눌지(분기를 넣으면 CFG로 가는 첫걸음).
- 변수 값을 `declarations`에만 둘지, 각 `step`에 "이 시점에 확정된 값"을 풀어서 둘지(상수 전파와 연결).
- 사람용 출력에서 `$pkgdir` 일상 작업을 어디까지 접을지.
- `marks`를 IR 안에 둘지 별도 파일로 둘지(IR을 판정과 분리해서 보관하고 싶다면 별도).
- 스키마 버전 관리: 필드 추가는 허용, 의미 변경은 `ir_version` 증가.
