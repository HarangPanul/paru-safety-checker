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
