# paru-safety-checker
arch linux에서 paru로 aur패키지를 설치하기 전 ai를 사용해서 PKGBUILD파일을 검사하는 간단한 프로젝트

## 사용법

```sh
pip install .
export ANTHROPIC_API_KEY=...
paru-safe -S some-aur-package
```

`paru-safe`는 `-S` 설치 명령일 때만 AUR 저장소를 받아 PKGBUILD / `*.install` / 패치를 AI로 검사하고,
결과(safe / caution / danger)를 보여준 뒤 승인하면 `paru`를 실행합니다. 그 외 명령은 그대로 paru에 전달됩니다.

- `danger`: 기본 차단. `--safe-force`를 붙이면 `yes`를 직접 입력해 진행할 수 있습니다.
- 분석/다운로드 실패 시 자동 통과하지 않고(fail-closed) 명시적 확인을 요구합니다.
- 환경변수: `ANTHROPIC_API_KEY`, `PARU_SAFE_MODEL`, `ANTHROPIC_BASE_URL`

AI 판정은 보조 수단이며 완전한 안전을 보장하지 않습니다. 중요한 패키지는 PKGBUILD를 직접 확인하세요.

## 규칙 기반 사전 검사

`paru_safety_checker/heuristics.py`의 규칙(약 100개)이 AI 호출 전에 PKGBUILD / `*.install` / 패치를 검사합니다.
심각도는 세 단계입니다.

- `danger`: 차단. AI를 호출하지 않으며, AI가 `safe`라고 해도 뒤집지 못합니다.
- `caution`: 설치 전 사용자 확인을 요구합니다.
- `info`: 약한 힌트. 판정에는 영향이 없고 리포트와 AI 프롬프트에만 표시됩니다.

주요 분류: 원격 코드 실행(`curl|sh`, `bash <(curl)`, 디코드 후 실행, 명령어 이름 난독화), 리버스/바인드 셸, 자격증명·지갑·브라우저 데이터 접근과 유출,
지속성(cron, systemd, shell rc, ld.so.preload, sudoers), 권한 상승(setuid, UID 0), 방어 회피(로그·히스토리 삭제, 보안 도구 비활성화),
파괴(`rm -rf /`, 디스크 쓰기), 채굴, 알려진 사건의 패키지명, 리뷰어를 노린 프롬프트 인젝션·유니코드 속임수(Trojan Source),
소스 URL 검사(http/IP/단축URL/GitHub 사칭/체크섬 SKIP/체크섬 없음), PKGBUILD 최상위 코드 실행(파싱만 해도 실행됨), 심볼릭 링크·바이너리 파일.
`$url` 같은 단순 변수는 펼쳐서 소스 URL을 검사하고, "다운로드 + `/tmp`에서 실행" 같은 조합은 danger로 올립니다.

## 규칙 기반 검사의 오탐 측정

인기 AUR 패키지(정상으로 가정)의 PKGBUILD를 모아 규칙 검사를 돌려 오탐률을 봅니다.

```sh
# 1) 수집: 메타데이터 덤프 1회 + 패키지별 순차 clone (기본 2~3초 간격, 중단 후 재실행하면 이어서 진행)
python -m paru_safety_checker.corpus collect --out data/corpus --count 500

# 2) 측정: 레벨별 비율, 규칙별 오탐 패키지 수와 예시
python -m paru_safety_checker.corpus measure --corpus data/corpus --examples 3
```

AUR이 429/403을 돌려주면 지수 백오프로 재시도하고, 계속되면 중단합니다. `data/`는 git에서 제외됩니다.
