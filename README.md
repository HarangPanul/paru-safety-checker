# paru-safety-checker
arch linux에서 paru로 aur패키지를 설치하기 전, **PKGBUILD가 무엇으로 이루어져 있고 무엇을 하는지 사용자가 더 빠르게 이해하도록 돕는 도구**

## 목표와 원칙

이 도구는 "안전하다/위험하다"를 대신 판정하지 않습니다. 사용자가 PKGBUILD를 그냥 읽는 것보다 빨리, 빠뜨리지 않고
이해하게 만드는 것이 목적이고, 설치 여부는 언제나 사용자가 정합니다.

1. **구성과 하는 일을 먼저 보여준다.** 소스(URL, 체크섬, VCS 고정 여부), 의존성, 어느 함수가 무엇을 하는지,
   인터넷에서 가져오는 것, 빌드 디렉터리 밖 파일 접근, 실행하는 명령, 설치 훅(root), 파일을 파싱만 해도 실행되는 코드를
   의심 여부와 무관하게 항상 보여줍니다.
2. **눈여겨볼 곳을 표시한다.** 규칙과 허용 목록은 판정이 아니라 "여기는 직접 읽어 보라"는 표시입니다.
   알려진 정상 구문만 조용히 넘기고 나머지는 전부 표시하는 방식(default-deny)이므로 정상 패키지에도 표시가 생기며, 이는 결함이 아니라 설계입니다.
   경고가 없다는 것은 **안전하다는 보증이 아닙니다.**
3. **이해하지 못한 부분을 숨기지 않는다.** 파싱 실패, 잘린 파일, 실행 시점에 정해지는 명령, 읽지 못한 파일은 요약이 다루지 못한 구간으로
   분명히 표시합니다. 요약만 보고 원문을 읽지 않게 만드는 것이 이 도구의 가장 큰 위험이기 때문입니다.
4. **모든 설명은 원문 줄로 이어진다.** 사용자가 직접 확인할 수 있어야 믿을 수 있으므로, 보고하는 내용에는 파일과 줄 번호를 붙입니다.
5. **설치를 막지 않는다.** 도구가 거부하는 경로는 없습니다. 눈여겨볼 곳이 많거나 검토가 불완전할수록 확인 절차만 무거워집니다
   (`caution`은 `y`, `danger`나 검토 실패는 `yes`를 직접 입력).
6. **AI는 읽는 일을 돕는 보조다.** 규칙이 파싱한 사실 위에서 요약하고, 규칙이 예상하지 못한 우회·난독화·목적과 동작의 불일치를 찾습니다.
   경고를 더할 수만 있고 줄일 수는 없으며, AI가 "문제없다"고 해도 규칙이 표시한 것은 지워지지 않습니다.

### 현재 구현 상태
- 구성·하는 일: **행위 보고서**(네트워크, 빌드 밖 파일 접근, 설치 훅, 파싱 시점 코드, 실행 명령)까지 구현되어 있습니다.
  소스·의존성·함수별 한 장 요약, 원문 줄에 연결된 AI 요약은 아직 없습니다([KNOWN_ISSUES.md](KNOWN_ISSUES.md)).
- 눈여겨볼 곳 표시: 규칙(약 120개), 허용 목록, AI 검토가 구현되어 있습니다. 내부적으로는 `safe`/`caution`/`danger` 세 단계를 쓰며,
  화면에는 `safe`를 "경고 없음"(NO FINDINGS)으로 표시합니다.

## 사용법

```sh
pip install .
export ANTHROPIC_API_KEY=...
paru-safe -S some-aur-package
```

`paru-safe`는 `-S` 설치 명령일 때만 AUR 저장소를 받아 아래를 순서대로 보여준 뒤 확인을 받고 `paru`를 실행합니다.
그 외 명령은 그대로 paru에 전달됩니다.

1. **행위 보고서**: 네트워크 접근, 빌드 디렉터리 밖 파일 접근(읽기/쓰기/삭제), 설치 훅, 파싱 시점 코드, 실행 명령.
   `$srcdir`/`$pkgdir` 안의 일상적인 파일 작업은 개수만 보여주며, `--safe-verbose`를 붙이면 전부 나열합니다.
2. **눈여겨볼 곳**: 규칙·허용 목록·AI가 표시한 항목(`caution` / `danger`).
3. **확인**: 표시가 없어도 항상 묻습니다(`[y/N]`, 표시가 없다는 것이 안전하다는 뜻은 아닙니다). `caution`도 `[y/N]`, `danger`나 AI 검토 실패 등 검토가 불완전하면 `yes`를 직접 입력합니다.
   여러 패키지는 한 번에 묻습니다. 답을 받을 수 없으면(입력 없음) 설치하지 않습니다. 검토 대상이 아닌 명령(`-S` 아님, 공식 저장소 패키지)은 그대로 paru에 전달합니다.

- 분석/다운로드 실패도 자동 통과하지 않고(fail-closed) `yes` 입력을 요구합니다.
- 환경변수: `ANTHROPIC_API_KEY`, `PARU_SAFE_MODEL`, `ANTHROPIC_BASE_URL`

이 도구의 출력은 이해를 돕는 자료이며 안전을 보장하지 않습니다. 한계는 [KNOWN_ISSUES.md](KNOWN_ISSUES.md)에 있습니다.

## 처리 순서

1. **가져오기**: AUR 저장소를 clone하고 PKGBUILD, `*.install`, 패치 등을 읽습니다.
2. **전처리** (`preprocess.py`): PKGBUILD와 `*.install`에서 **주석을 제거하고 명령 1개당 1줄로 폅니다.**
   `;`, `&&`, `||`, 줄바꿈, `\` 이음줄로 이어진 명령을 나누고 `if`/`then`/`fi` 같은 키워드는 버립니다.
   파이프라인은 한 줄로 두고, `$(...)`는 해당 명령 안에 그대로 둡니다. 모든 줄은 원본 줄 번호를 유지합니다.
   결과는 `bash --pretty-print`(스크립트를 실행하지 않고 파싱만 함)와 교차검증하며, 두 파서가 다르게 읽으면
   코드가 가려졌을 수 있으므로 `parser-mismatch`로 경고합니다. **bash 4.4 이상이 필요합니다.**
3. **구조화** (`parsed.py`): 파일 하나를 **한 번만** 파싱해서 `ParsedFile`로 만듭니다. 명령을 단어로 나누고(따옴표 제거),
   파이프라인 단계, 래퍼(`sudo`/`env`/`nice` …) 안쪽 프로그램, `sh -c '...'`·`eval '...'` 안의 명령 문자열, 리다이렉션,
   변수·배열 정의와 각 항목의 줄 번호를 담습니다. 이후 검사기는 스크립트 텍스트가 아니라 이 결과를 받습니다.
   원문을 직접 읽는 곳은 눈에 보이지 않는 문자 검사, bash 교차검증, 잘림 표시 확인 세 군데뿐이고(`raw_text()`), 테스트가 이를 고정합니다.
4. **분석**: 파싱 결과에 대해 규칙(`heuristics.py`, `cmdrules.py`), 허용 목록(`strict.py`), 행위 보고서(`activity.py`)를 실행합니다.
   제거된 주석의 내용도 리뷰어를 노린 문구(프롬프트 인젝션)는 검사합니다.
5. **AI**: 전처리된 텍스트(주석 제거, 원본 줄 번호 포함)와 위 결과를 받아 규칙이 예상하지 못한 것을 찾습니다.
6. **보고와 확인**: 행위 보고서, 발견 사항을 보여주고 사용자가 설치 여부를 고릅니다.

## 규칙 기반 사전 검사

`paru_safety_checker/heuristics.py`의 규칙(약 100개)이 PKGBUILD / `*.install` / 패치를 검사합니다.
심각도는 두 단계입니다.

- `danger`: 강하게 표시(`yes` 입력 필요). AI가 문제없다고 해도 뒤집지 못합니다.
- `caution`: 설치 전 직접 읽어 보고 확인하도록 요구합니다.

주요 분류: 원격 코드 실행(`curl|sh`, `bash <(curl)`, 디코드 후 실행, 명령어 이름 난독화), 리버스/바인드 셸, 자격증명·지갑·브라우저 데이터 접근과 유출,
지속성(cron, systemd, shell rc, ld.so.preload, sudoers), 권한 상승(setuid, UID 0), 방어 회피(로그·히스토리 삭제, 보안 도구 비활성화),
파괴(`rm -rf /`, 디스크 쓰기), 채굴, 알려진 사건의 패키지명, 리뷰어를 노린 프롬프트 인젝션·유니코드 속임수(Trojan Source),
소스 URL 검사(http/IP/단축URL/GitHub 사칭/체크섬 SKIP/체크섬 없음), PKGBUILD 최상위 코드 실행(파싱만 해도 실행됨), 심볼릭 링크·바이너리 파일.
`$url` 같은 단순 변수는 펼쳐서 소스 URL을 검사하고, "다운로드 + `/tmp`에서 실행" 같은 조합은 danger로 올립니다.

### 파싱된 명령을 읽는 규칙 (`cmdrules.py`)

정규식은 단어·따옴표·파이프의 경계를 추측해야 합니다. `cmdrules.py`의 규칙은 이미 나뉜 명령을 받으므로
`c''url x | "ba"sh`, `curl x | tee f | sh`, `curl x | sudo -u nobody env bash -s`, `sh -c 'curl x | sh'`,
`cp x /etc//pam.d/../sudoers`, `rm -rf /./` 같은 변형을 그대로 같은 명령으로 봅니다.

- 파이프 규칙(`pipe-to-shell`, `base64-exec`, `decode-exec`, `network-pipe-shell`, `echo-to-shell`, `fetched-xargs-exec`)은
  **상류 단계 전체**를 봅니다. `(curl x) | sh`, `{ curl x; echo; } | sh`, `curl x | (cd /tmp; sh)`처럼 괄호·중괄호를 건너는 파이프,
  `cat <(curl x) | sh`, `sh <<< "$(curl x)"`처럼 치환 결과를 입력으로 받는 경우, `source /dev/stdin`, `busybox sh`,
  `xargs sh -c`도 같은 방식으로 따라갑니다. 반대로 `bash -c '...'`나 스크립트 파일 인자처럼 파이프 입력을 읽지 않는 경우와
  따옴표 안의 문자열(`echo 'curl x | sh'`)은 위험으로 보지 않습니다.
  단계별 요약(`upstream_tags`)을 한 번만 계산해 재사용하므로 파이프가 수천 단계여도 선형 시간입니다.
- 파일 규칙(`live-system-write`, `sudoers-passwd-write`, `pacman-config-write`, `install-system-files`)은 명령이 **쓰거나 지우는 경로**를
  `//`, `.`, `..`을 정리하고, 파일에서 한 번만 대입된 변수(`d=/etc; cp x $d/y`)를 펼친 뒤 판단합니다. `mv`의 원본은 지워지는 것으로,
  `tar -C`, `unzip -d`, `7z -o`로 푸는 위치는 쓰는 것으로 봅니다. `.install`에서는 상대 경로를 `/` 기준으로 봅니다(pacman이 `/`에서 실행하기 때문).
- 이름 규칙(`sudo`, `kernel-module`, `setcap` …)은 프로그램 이름만 봅니다. 그래서 `etc/modprobe.d/` 경로나 `echo sudo`는 걸리지 않습니다.
- 데이터 흐름 규칙: `fetch-then-execute`(내려받은 파일을 나중에 실행), `home-persistence-write`(빌드가 `~/.bashrc`, 자동 시작,
  사용자 유닛, `authorized_keys`에 씀).
- 각 규칙에는 같은 id의 정규식이 **예비 규칙**으로 남아 있어, 파서가 읽지 못한 줄과 쉘이 아닌 파일(패치, `.hook`)에서만 실행됩니다.
- 한 줄이 2000자를 넘으면 열린 간격(`[^\n]*`)이 있는 정규식은 건너뛰고 `overlong-line`으로 경고합니다(이차 시간 방지).
  파싱 기반 규칙과 허용 목록은 줄 전체를 그대로 봅니다.

### 허용 목록 방식(default-deny)

정규식은 "알려진 나쁜 패턴"만 찾으므로 새 수법은 통과합니다. 그래서 `paru_safety_checker/strict.py`가 PKGBUILD와
`*.install`의 쉘 코드를 직접 해석해서, **일반적인 패키징 명령이 아니면 전부 경고**합니다.

- 실행되는 모든 명령(`$(...)`, 백틱, 파이프, `find -exec`, `xargs`, 래퍼 명령 안쪽 포함)이 허용 목록에 있어야 합니다.
  `install` 훅은 root로 실행되므로 훨씬 짧은 목록을 씁니다.
- 변수로 만든 명령, `python -c` / `perl -e` / heredoc·파이프로 넘기는 인라인 코드, 인자로 코드를 실행하는 `sed e/w/r`,
  `find -fprint`, `tar --to-command`, `git config alias`, 파싱되지 않는 쉘, 함수 밖(최상위) 코드와 파싱 시점 `$(...)`도 경고합니다.
- 저장소에 있는 `.sh`/`.py` 같은 스크립트와 알 수 없는 파일은 "패턴만 확인했을 뿐 이해하지 못함"으로 경고합니다.
- AI는 항상 호출되며(규칙이 이미 `danger`를 찾았어도) 판정을 올리기만 할 수 있습니다. 분석기 자체가 실패해도 경고로 처리합니다.

남아 있는 한계와 미해결 항목은 [KNOWN_ISSUES.md](KNOWN_ISSUES.md)에 기록해 두었습니다.

### 검토하지 못한 것과 외부에서 들여오는 것은 항상 경고

미탐보다 오탐이 낫다는 원칙으로, 정상 여부와 상관없이 아래는 모두 `caution`(설치 전 확인)입니다.

- 검토하지 못한 파일: 바이너리(PNG 포함), 읽을 수 없는 파일, 크기 제한으로 잘린 파일·누락된 파일, 심볼릭 링크, git submodule
- `source`의 모든 원격 URL(https·체크섬 유무와 무관), 고정되지 않은 VCS 소스, 변수라서 해석할 수 없는 소스
- 빌드 중 의존성을 내려받는 도구: go / cargo / npm·pnpm·yarn / pip·`python -m build`(격리 빌드) / gem / maven·gradle / dotnet 등
- 빌드 중 `git clone`·`git fetch`, `curl`/`wget`, 설치 도구(`pacman -S`, `docker pull` 등)
- 공식 저장소에 없는 의존성: paru가 AUR에서 받아 빌드하지만 `paru-safe`가 검토하지 않으므로, 명령줄에 직접 적어야 검토됩니다.

## 규칙 기반 검사의 오탐 측정

인기 AUR 패키지(정상으로 가정)의 PKGBUILD를 모아 규칙 검사를 돌려 오탐률을 봅니다.

```sh
# 1) 수집: 메타데이터 덤프 1회 + 패키지별 순차 clone (기본 2~3초 간격, 중단 후 재실행하면 이어서 진행)
python -m paru_safety_checker.corpus collect --out data/corpus --count 500

# 2) 측정: 레벨별 비율, 규칙별 오탐 패키지 수와 예시
python -m paru_safety_checker.corpus measure --corpus data/corpus --examples 3
```

대상을 다르게 고르거나 폴더로 내보낼 수도 있습니다.

```sh
# 최근 30일 안에 바뀐 패키지 중 투표가 5표 이하인 것 (새 악성 패키지가 몰리는 구간)
python -m paru_safety_checker.corpus collect --out data/corpus --count 300 --strategy recent --since-days 30 --max-votes 5 --min-votes 0
# 고아(orphan) 패키지나 out-of-date 패키지만
python -m paru_safety_checker.corpus collect --out data/corpus --only orphan --min-votes 0
# 직접 모은 목록(한 줄에 패키지 하나, # 주석 가능)
python -m paru_safety_checker.corpus collect --out data/corpus --names targets.txt
# 패키지별 폴더로 내보내기: data/targets/<label>/<패키지>/PKGBUILD (label을 malicious/benign으로 두면 experiments/yesno_logprob.py가 그대로 읽음)
python -m paru_safety_checker.corpus export --corpus data/corpus --out data/targets --label benign
```

AUR이 429/403을 돌려주면 지수 백오프로 재시도하고, 계속되면 중단합니다. `data/`는 git에서 제외됩니다.

## 라이선스

[Apache-2.0](LICENSE) © 2026 HarangPanul. 저작권 고지는 [NOTICE](NOTICE)에 있습니다.
