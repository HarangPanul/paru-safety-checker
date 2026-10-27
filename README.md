# paru-safety-checker
arch linux에서 paru로 aur패키지를 설치하기 전 PKGBUILD를 검사해서 사용자에게 경고하는 프로젝트

## 목표와 원칙

1. **미탐을 최대한 없앤다.** 오탐은 감수합니다. "나쁜 패턴을 찾는" 방식만으로는 새 수법을 놓치므로, 알려진 정상 구문만
   조용히 통과시키고 나머지는 전부 경고하는 방식(default-deny)을 기본으로 합니다.
2. **설치를 막지 않는다.** 탐지하고 경고한 뒤 설치 여부는 사용자가 고릅니다. 도구가 거부하는 경로는 없습니다.
   위험할수록 확인 절차만 무거워집니다(`caution`은 `y`, `danger`나 검토 실패는 `yes`를 직접 입력).
3. **PKGBUILD가 하는 일은 전부 보고한다.** 의심스러운지와 무관하게, 인터넷에서 가져오는 것, 빌드 디렉터리 밖 파일 접근,
   실행하는 명령, 설치 훅(root), 파일을 파싱만 해도 실행되는 코드를 항상 보여줍니다.
4. **AI는 새로운 수법을 막는 마지막 방어선이다.** 규칙과 허용 목록이 예상하지 못한 우회, 난독화, 목적과 동작의 불일치를 찾습니다.
   규칙이 이미 보고한 것을 반복하거나 기각하는 것이 일이 아니며, 경고를 더할 수만 있고 줄일 수는 없습니다.

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
2. **발견 사항**: 규칙·허용 목록·AI가 찾은 경고(`caution` / `danger`).
3. **확인**: 경고가 없으면 바로 진행, `caution`이면 `[y/N]`, `danger`나 AI 검토 실패 등 검토가 불완전하면 `yes` 입력.

- 분석/다운로드 실패도 자동 통과하지 않고(fail-closed) `yes` 입력을 요구합니다.
- 환경변수: `ANTHROPIC_API_KEY`, `PARU_SAFE_MODEL`, `ANTHROPIC_BASE_URL`

AI 판정은 보조 수단이며 완전한 안전을 보장하지 않습니다. 한계는 [KNOWN_ISSUES.md](KNOWN_ISSUES.md)에 있습니다.

## 처리 순서

1. **가져오기**: AUR 저장소를 clone하고 PKGBUILD, `*.install`, 패치 등을 읽습니다.
2. **전처리** (`preprocess.py`): PKGBUILD와 `*.install`에서 **주석을 제거하고 명령 1개당 1줄로 폅니다.**
   `;`, `&&`, `||`, 줄바꿈, `\` 이음줄로 이어진 명령을 나누고 `if`/`then`/`fi` 같은 키워드는 버립니다.
   파이프라인은 한 줄로 두고, `$(...)`는 해당 명령 안에 그대로 둡니다. 모든 줄은 원본 줄 번호를 유지합니다.
   결과는 `bash --pretty-print`(스크립트를 실행하지 않고 파싱만 함)와 교차검증하며, 두 파서가 다르게 읽으면
   코드가 가려졌을 수 있으므로 `parser-mismatch`로 경고합니다. **bash 4.4 이상이 필요합니다.**
3. **분석**: 전처리된 줄에 대해 규칙(`heuristics.py`), 허용 목록(`strict.py`), 행위 보고서(`activity.py`)를 실행합니다.
   제거된 주석의 내용도 리뷰어를 노린 문구(프롬프트 인젝션)는 검사합니다.
4. **AI**: 전처리된 텍스트(주석 제거, 원본 줄 번호 포함)와 위 결과를 받아 규칙이 예상하지 못한 것을 찾습니다.
5. **보고와 확인**: 행위 보고서, 발견 사항을 보여주고 사용자가 설치 여부를 고릅니다.

## 규칙 기반 사전 검사

`paru_safety_checker/heuristics.py`의 규칙(약 100개)이 PKGBUILD / `*.install` / 패치를 검사합니다.
심각도는 두 단계입니다.

- `danger`: 강한 경고(`yes` 입력 필요). AI가 `safe`라고 해도 뒤집지 못합니다.
- `caution`: 설치 전 사용자 확인을 요구합니다.

주요 분류: 원격 코드 실행(`curl|sh`, `bash <(curl)`, 디코드 후 실행, 명령어 이름 난독화), 리버스/바인드 셸, 자격증명·지갑·브라우저 데이터 접근과 유출,
지속성(cron, systemd, shell rc, ld.so.preload, sudoers), 권한 상승(setuid, UID 0), 방어 회피(로그·히스토리 삭제, 보안 도구 비활성화),
파괴(`rm -rf /`, 디스크 쓰기), 채굴, 알려진 사건의 패키지명, 리뷰어를 노린 프롬프트 인젝션·유니코드 속임수(Trojan Source),
소스 URL 검사(http/IP/단축URL/GitHub 사칭/체크섬 SKIP/체크섬 없음), PKGBUILD 최상위 코드 실행(파싱만 해도 실행됨), 심볼릭 링크·바이너리 파일.
`$url` 같은 단순 변수는 펼쳐서 소스 URL을 검사하고, "다운로드 + `/tmp`에서 실행" 같은 조합은 danger로 올립니다.

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

AUR이 429/403을 돌려주면 지수 백오프로 재시도하고, 계속되면 중단합니다. `data/`는 git에서 제외됩니다.

## 라이선스

[Apache-2.0](LICENSE) © 2026 HarangPanul. 저작권 고지는 [NOTICE](NOTICE)에 있습니다.
