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

## 규칙 기반 검사의 오탐 측정

인기 AUR 패키지(정상으로 가정)의 PKGBUILD를 모아 규칙 검사를 돌려 오탐률을 봅니다.

```sh
# 1) 수집: 메타데이터 덤프 1회 + 패키지별 순차 clone (기본 2~3초 간격, 중단 후 재실행하면 이어서 진행)
python -m paru_safety_checker.corpus collect --out data/corpus --count 500

# 2) 측정: 레벨별 비율, 규칙별 오탐 패키지 수와 예시
python -m paru_safety_checker.corpus measure --corpus data/corpus --examples 3
```

AUR이 429/403을 돌려주면 지수 백오프로 재시도하고, 계속되면 중단합니다. `data/`는 git에서 제외됩니다.
