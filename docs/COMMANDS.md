# 명령 표와 이름 해석 설계 (초안)

> 상태: **초안, 아직 구현 없음.** 형식은 나중에 바꾸기 어려우므로 구현 전에 이 문서로 먼저 정합니다.
> 관련: `strict.py`(지금의 허용 목록), `ir.py`(`ops`와 `area`), `docs/IR.md`, `docs/ROADMAP.md`의 접근 위치 분석.

## 목적
지금 `strict.py`는 "무해한 명령 이름" 목록(`BUILD_ALLOWED`, `HOOK_ALLOWED`)과, `classify()` 안에 흩어진 인자 검사(`sed`의 `e`/`w`/`r`, `awk`의 `system`, `find -exec`, `tar --to-command` 등)로 모르는 명령을 가려냅니다. 이를 **"명령이 무엇을 하는가"를 적은 표**로 바꿉니다.

- 표는 사실만 적습니다: 이 명령은 (이 인자로) 무엇을 읽고, 쓰고, 실행하고, 내려받고, 올리는가.
- "그래서 우려인가"는 표가 아니라 **정책**이 정합니다: 효과 × 위치(`area`) × 실행 맥락(명령이 있는 함수의 역할).
- 표에 없는 명령은 계속 default-deny(`unknown-command`)입니다.

## 효과의 종류
| 효과 | 뜻 |
|---|---|
| `read` | 파일을 읽는다 |
| `write` | 파일을 만들거나 바꾼다 |
| `delete` | 파일을 지운다 |
| `perm` | 권한·소유자·capability를 바꾼다 (`chmod`, `chown`, `setcap`) |
| `exec` | 다른 프로그램이나 코드를 실행한다 (대상 종류: 파일 / 문자열 / 표준입력 / 나머지 명령) |
| `fetch` | 네트워크에서 내려받는다 |
| `upload` | 네트워크로 보낸다 |
| `system` | 시스템 상태를 바꾼다 (사용자, 커널 모듈, 서비스, 패키지 설치) |
| `spawn` | 뒤에서 계속 도는 프로세스를 만든다 |

IR의 `ops`(`fetch`, `exec`, `read`, `write`, `delete`, `chmod`, `install-pkg`, `decode`, `spawn`, `other`)와 같은 틀이며, 구현할 때 하나로 합칩니다(`upload`, `system`은 새로 추가).

## 표의 형식
명령 하나가 한 항목입니다. 코드가 아니라 **정해진 어휘**로 적습니다(람다 없음).

```
이름[, 별칭...]   효과=대상 [조건]  ...
    ex: <명령줄> => <기대 효과>      # 항목마다 예시가 곧 테스트
    note: <이 항목이 왜 이렇게 적혔는지 한 줄>
```

### 대상(역할) 어휘
`@args` 위치 인자 전체 · `@args[:-1]`, `@args[-1]` 슬라이스 · `@opt(-o)` 옵션 값 · `@url` URL인 인자 · `@script` 스크립트 문자열 · `@cmd` 나머지를 명령으로 실행 · `@stdin` · `@none`

### 조건
`[-i]` 이 플래그가 있을 때만 · `[!-n]` 없을 때만 · `[script~e|w|r]` 스크립트에 이 명령이 있을 때 · `[args~::]` 인자 모양

### 예시
```
cat           read=@args
cp, mv        read=@args[:-1]  write=@args[-1]
rm            delete=@args
sed           read=@args  write=@args[-i]  exec=@script[script~e]  write=@script[script~w]  read=@script[script~r]
awk, gawk     read=@args  exec=@script[script~system|getline|pipe]  exec=@opt(-f)
curl          fetch=@url  upload=@url[-d|-F|-T|--data*|--form|--upload-file]  write=@opt(-o)
tar           read=@args  write=@args[-x]  exec=@opt(--to-command|--checkpoint-action)
useradd, groupadd, userdel, groupdel  system=users
sudo, env, time, xargs   exec=@cmd
```

### 규칙
1. **적히지 않은 옵션은 "효과 불명"이다.** 무시하지 않습니다. 표가 불완전해도 안전한 쪽으로 틀리게 하기 위해서입니다. 항목은 자기가 다루는 옵션 범위를 `covers=`로 적을 수 있고, 범위 밖의 옵션이 오면 불명으로 처리합니다.
2. **계열과 별칭.** `gmake`는 `make`의 별칭, 압축 도구·컴파일러는 계열 하나를 상속합니다.
3. **감싸는 명령**(`sudo`, `env`, `time`, `xargs`, `nohup`)은 특별 처리하지 않고 `exec=@cmd`로 적습니다. 지금 코드의 `BENIGN_WRAPPERS`/`STOP_WRAPPERS`/`views()`가 이 표로 합쳐집니다.
4. **맥락별 차이**는 항목에 `hook:`로 덧씁니다(설치 훅에서는 `sed -i`를 `system`으로 본다 등). 정책에 쓸 값을 바꾸는 게 아니라 효과 자체가 다를 때만 씁니다.
5. 항목마다 `ex:`가 1개 이상 있어야 하고, 모든 `ex:`는 자동으로 시험됩니다.
6. **점검 도구**(`python -m paru_analyzer.commands --check`): 중복, `note` 누락, 예시 누락, 알 수 없는 어휘, 정렬을 확인합니다.
7. 표에 버전을 붙이고 IR에 남깁니다(결과 재현용).

## 실행 맥락: 명령이 어느 함수에 있는가
같은 효과도 **언제, 누구 권한으로 실행되는가**에 따라 정상이기도 하고 위험하기도 합니다. 예를 들어 `useradd`나 `systemctl enable`(`system` 효과)은 `post_install()`에서는 흔하지만 `build()`나 `package()`에 있으면 빌드가 시스템을 건드리는 것이므로 위험합니다. 인자에 따라 효과 자체가 갈리는 명령도 있습니다(`makepkg -i`는 설치까지 하므로 `system`, `-i`가 없으면 빌드만이라 `system`이 아닙니다. `pacman -S`와 `-Q`도 마찬가지). 그래서 표(인자 → 효과)와 별개로 **명령이 있는 함수의 역할**을 정책의 입력에 넣습니다.

| 역할 | 어디 | 누가 / 언제 |
|---|---|---|
| `parse` | 함수 밖(최상위), `pkgver()` | makepkg가 파일을 읽을 때, 일반 사용자 (의존성 해석 중에도 실행될 수 있음) |
| `build` | `prepare()`, `build()`, `check()` | 일반 사용자, 빌드 중 |
| `package` | `package()`, `package_<이름>()` | fakeroot 안의 일반 사용자, 패키지 만들 때 |
| `hook` | `.install`의 `pre_install`, `post_install`, `pre_upgrade`, `post_upgrade`, `pre_remove`, `post_remove` | **root, 실제 시스템**, 설치·제거 때 |
| `unknown` | 호출되는 곳을 알 수 없는 함수 | 가장 엄격한 쪽(`build`)으로 봄 |

- 보조 함수는 **호출 그래프**로 역할을 정합니다. `_setup()`을 `build()`와 `post_install()`이 모두 부르면 두 역할의 합집합입니다. 어디서도 부르지 않는 함수는 `unknown`입니다.
- `IR`의 단위가 이미 `runs`(`as-user`, `as-root-on-install`, `at-parse`)를 가지고 있으므로, 이 역할은 `runs`를 세분화한 것입니다.

## 정책 (표와 분리)
표 위에 올라가는 판정 규칙이며, 표를 건드리지 않고 바꿉니다. 입력은 **효과 × 위치(`area`) × 역할**이고, 결과는 통과 · `expected`(보여 주기만) · 우려 중 하나입니다.

| 효과 | `parse` | `build` / `package` | `hook` |
|---|---|---|---|
| `read` | 통과 (민감한 경로는 기존 경로 규칙이 따로 표시) | 통과 | 통과 |
| `write`, `delete` | 우려 | `srcdir`, `pkgdir`, `tmp`는 통과, `home`, `system`, `unresolved`는 우려 | 그 패키지 자신의 파일은 통과, 다른 곳은 기존 경로 규칙(`live-system-write` 등) |
| `perm` | 우려 | `pkgdir` 안은 통과, 그 밖은 우려 | 기존 규칙(`setuid`, `setcap` 등) |
| `exec` 파일 | 우려 | 소스·빌드 트리(`./x`, `$srcdir/x`)는 **expected**, 그 밖은 우려 | 우려 |
| `exec` 문자열 / 표준입력 | 안의 명령을 풀어서 같은 표로 검사, 풀 수 없으면 우려 | 같음 | 같음 |
| `fetch` | 우려 | 기존 `build-time-download`, `dependency-fetch` 등이 맡음 | 우려 (`install-hook-network`) |
| `upload` | 우려 | 우려 | 우려 |
| `system` | 우려 | **우려** (빌드가 시스템 상태를 바꾸면 안 됨) | 통과하되 기존 규칙(`user-management`, `kernel-module`, `systemd` 등)이 표시 |
| `spawn` | 우려 | 우려 | 우려 |

- 즉 `system`은 `hook`에서는 "정상적인 설치 동작이라 표시만", `build`/`package`/`parse`에서는 우려입니다. 인자 때문에 효과가 갈리는 경우(`makepkg -i`, `pacman -S`)는 표가 `system`으로 적고, 정책이 역할로 판정합니다.
- 이 표는 시작점이며, 실제 값은 `measure`로 오탐과 미탐을 보면서 조정합니다.

## 이름 해석: 함수와 별칭이 명령 이름을 덮어쓰는 경우

### 지금 코드의 문제
1. **함수 이름이면 검사하지 않는다.** `classify()`는 `name in local_functions`이면 바로 통과시킵니다. 함수 본문은 따로 검사되지만, 같은 이름의 진짜 명령(`cp`, `curl`)이 가질 효과는 검사하지 않고, 이름 덮어쓰기 자체도 표시하지 않습니다.
2. **절대 경로가 이름으로 접힌다.** `_normalise()`는 `/tmp/x/cp`를 `cp`로 바꿔서 허용 목록에 맞춥니다. `/tmp`에 둔 가짜 `cp`가 진짜 `cp`처럼 통과합니다.
3. **별칭은 따로 보지 않는다.** `alias`는 특정 이름(`sudo`, `ssh`, ...)을 정규식으로 잡을 뿐, 별칭이 풀리는 호출 지점은 따라가지 않습니다.
4. **`hash -p 경로 이름`은 허용 목록에 있다.** `hash`가 허용돼 있어 `hash -p /tmp/evil ls`로 이름이 가리키는 프로그램을 바꿀 수 있습니다.

### bash가 이름을 찾는 순서
별칭(`expand_aliases`가 켜져 있을 때만, 정의된 뒤에 읽는 줄부터) → 함수 → 내장 명령 → `PATH`(해시 표 포함) → `command_not_found_handle`.
우회 문법: `command x`는 별칭과 함수를 건너뛰고, `builtin x`는 함수를 건너뛰고, `\x`와 따옴표는 별칭만 건너뜁니다(함수는 그대로 호출됨), `env x`와 경로로 쓰면 둘 다 건너뜁니다.

### 해석 규칙 (보수적으로)
호출 하나는 아래 순서로 해석되고, **어느 한 쪽일 수 있으면 모두를 검사**합니다.

1. 단어가 `$`로 시작하거나 `__SUB__`이면 `dynamic`.
2. `/`를 포함하면 **경로**다. 절대 경로는 시스템 실행 디렉터리(`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`)일 때만 그 이름의 표 항목으로 해석하고, 그 밖의 절대 경로와 상대 경로는 `exec` 파일로 본다(대상 위치로 정책이 판정).
3. 이름이 이 파일에서 **함수로 정의돼 있고** 같은 이름이 표·내장 명령에도 있으면, 호출은 "함수 본문 ∪ 진짜 명령"으로 검사한다(정의 순서, 분기, `unset -f`는 따라가지 않고 정의된 적이 있으면 있다고 본다). 이름이 `command`/`builtin`으로 시작하면 진짜 명령만 본다. 함수만 있고 표에 없는 이름은 본문만 본다(지금과 같음).
4. 이름이 **별칭**이면 별칭 값을 한 번 풀어(재귀는 깊이 제한) 명령 문자열처럼 `flatten`으로 읽고 그 명령들을 검사한다. 값이 읽히지 않거나 `expand_aliases`를 알 수 없으면 우려.
5. 그렇지 않으면 표에서 찾는다. 없으면 `unknown-command`.

### 새 표시 (우려)
| 규칙 이름 | 언제 |
|---|---|
| `shadowed-command` | 함수나 별칭이 표·내장 명령의 이름을 덮어씀 (makepkg가 쓰는 `msg`, `msg2`, `warning`, `error`, `plain`, `plainerr`는 제외) |
| `command-lookup-change` | `hash -p`, `enable -n`, `command_not_found_handle` 함수 정의, `PATH` 변경(`path-modification`과 통합), `trap ... DEBUG` |
| `alias-definition` | `alias`로 별칭을 정의하거나 `shopt -s expand_aliases`를 켬 |

`trap`의 핸들러 문자열은 `sh -c`처럼 풀어서 같은 표로 검사합니다.

### 범위 밖 (알고 있는 한계)
- 정의 순서와 조건 분기까지 정확히 따라가지는 않습니다(정의된 적이 있으면 "있다"고 본 보수적 합집합).
- 다른 파일에서 `source`한 함수는 보이지 않습니다. `source`는 소스 안 파일이면 `exec 파일`(expected), 그 밖이면 우려입니다.
- 함수 이름이 `eval`로 만들어지면(`eval "$n() { ...; }"`) 이름은 알 수 없고, `eval` 문자열을 풀 수 없으면 우려입니다.

## 구현 순서
1. **표 형식과 읽는 코드**: 이 문서의 형식을 읽고 점검하는 모듈과 `--check`. 이 단계는 동작을 바꾸지 않는다.
2. **`strict.py`가 표를 쓰게 한다.** 허용 목록과 `classify()`의 인자 검사를 표로 옮긴다. 이전 코드와 같은 입력 8,735개의 결과가 같아야 한다.
3. **이름 해석 규칙(함수·별칭·경로)** 을 넣고 새 표시를 추가한다. 이 단계는 결과가 바뀌며 각 규칙을 시험으로 고정한다.
4. **함수 역할과 호출 그래프**를 만든다(`parse`/`build`/`package`/`hook`/`unknown`). 이 단계는 동작을 바꾸지 않는다.
5. **정책**을 올려서 `unknown-command`를 줄이고 `system`을 역할로 판정한다(소스 안 프로그램은 expected 등).
6. `ir.py`가 같은 표와 역할을 쓰게 한다.
