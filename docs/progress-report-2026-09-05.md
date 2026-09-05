# decomp_engine 개발 성과 및 진행 현황 보고서

- 작성일: 2026년 9월 5일
- 상태 확인 시각: 2026년 9월 5일 11:43 KST
- 보고 범위: A-series 마일스톤 및 이를 지원하는 구현·검증 작업
- 구현 기준 커밋: `39aa80b` — 원격 `master`에 푸시 완료
- 상태 기준: 작성 시점의 GitHub 마일스톤·이슈와 확인된 테스트 결과
- 저장소: [minsago-elite/decomp_thing](https://github.com/minsago-elite/decomp_thing)
- 개정 내용: 11:09 초안 이후 호출 관측 기준선 구현, LLVM CI 빌드 제한 및 완료된 CI 결과 반영

## 1. 제출용 요약

본 프로젝트는 Linux x86-64 ELF 바이너리를 분석하여 C 소스 및 빌드 가능한 소스 트리로 재구성하고,
재구성 결과의 구조와 동작을 검증하는 LLM 보조 도구를 개발하는 것을 목표로 한다.
현재 단일 파일 재구성, 다중 모듈 소스 트리 생성, 결정적 아카이브 출력, GCC 드라이버 대상 검증,
Clang/LLVM 정답 데이터 구축에 해당하는 A-series의 12개 마일스톤이 GitHub에서 완료 처리되어 있다.

최근에는 대규모 Clang/LLVM 분석을 위한 Kotlin/JVM 기반 원본 데이터 검증과 SQLite 기반 호출 관계
구성 기능을 구현하였다. 3개 샤드에 걸친 실제 ELF/DWARF 형식의 테스트 자료에서 호출 관측 12건을
중복 제거된 11개 호출 간선으로 구성하고, 결과를 원본에서 다시 유도하여 독립적으로 검증하였다.
이어 원본 기반 호출 관측 기준선 보고서의 생성·독립 검증을 구현하였으며, 최종 관련 테스트 85개가
모두 통과하였다. 별도의 LLVM CI 빌드·출처 검증 테스트는 36개 통과, 환경에 따른 생략 2개였다.
또한 LLVM 이미지 빌드에 시도별 시간 제한과 제한된 재시도를 추가하면서 기존의 고정 빌드 조건과
검증 절차를 유지하였다.

다만 GCC 컴파일러 엔진과 Clang/LLVM 전체 소스 트리의 재구성·동작 동등성 검증은 아직 진행 중이다.
확인된 최근 완료 CI의 Kotlin 작업은 1,336건 중 1,303건 통과, 29건 생략, 4건 실패였다.
전체 CI 성공, 실제 대규모 재구성 정확도, 배포·릴리스 승인까지 완료했다고 주장하지 않는다.
이후 개발은 A-series에 집중하며 B/C/D-series의 신규 작업은 보류한다.

## 2. A-series 진행 현황

| 구분 | 완료 | 진행 중 | 전체 |
|---|---:|---:|---:|
| 마일스톤 | 12 | 4 | 16 |
| 마일스톤에 속한 이슈 | 70 | 31 | 101 |

마일스톤 개수 기준 완료 비율은 75%, 이슈 개수 기준은 약 69%이다.
이는 계획 관리상의 개수 비율이며, 구현량·정확도·남은 소요 시간의 비율이 아니다.
남은 항목에는 전체 컴파일러 규모의 재구성과 동작 검증처럼 큰 작업이 포함된다.

### 완료 처리된 단계

| 단계 | 완료 처리된 범위 |
|---|---|
| A0 | 단일 파일 재구성 기반 |
| A1 | 벤치마크 프로그램 구조 복구 |
| A2 | 빌드 가능한 벤치마크 소스 트리 생성 |
| A3 | 다중 모듈 벤치마크 소스 트리 개선 |
| A4 | 결정적 소스 아카이브 출력 |
| A5 | 합성 아카이브 벤치마크 검증 |
| A6 | GCC 정확도 평가용 정답 데이터 구축 |
| A7 | GCC 드라이버 규모로 구조 복구 확장 |
| A8 | 빌드 가능한 GCC 드라이버 소스 트리 재구성 |
| A9 | GCC 드라이버 동작 충실도 검증 |
| A11 | 교차 도구 체인 검증 및 CI 강화 |
| A12 | Clang/LLVM 정확도 평가용 정답 데이터 구축 |

위 표는 [GitHub 마일스톤](https://github.com/minsago-elite/decomp_thing/milestones)의 완료 상태를 요약한 것이다.
과거 마일스톤의 완료 상태가 현재 확장 중인 모든 CI 경로의 성공이나, 모든 입력 바이너리에 대한
재구성 정확도를 뜻하지는 않는다. 합성·고정 응답 테스트 역시 실제 모델의 일반화 성능과 구분한다.

### 진행 중인 단계

| 단계 | 목적 | 완료 이슈 / 전체 이슈 |
|---|---|---:|
| [A10](https://github.com/minsago-elite/decomp_thing/milestone/14) | GCC 컴파일러 엔진 규모로 재구성 확장 | 0 / 4 |
| [A13](https://github.com/minsago-elite/decomp_thing/milestone/23) | Clang/LLVM 전체 트리 구조 정확도 확장 | 2 / 11 |
| [A14](https://github.com/minsago-elite/decomp_thing/milestone/24) | 빌드 가능한 Clang/LLVM 전체 소스 트리 재구성 | 0 / 8 |
| [A15](https://github.com/minsago-elite/decomp_thing/milestone/25) | Clang/LLVM 전체 트리 동작 충실도 검증 | 6 / 16 |

## 3. 주요 구현 성과

### 3.1 재구성 및 결과물 관리 기반

저장소는 바이너리 분석 결과를 이용한 함수·모듈 구성, 소스 트리 생성, 빌드 검증 및 결정적 아카이브
출력 경로를 제공한다. 재구성 결과에는 소스뿐 아니라 모듈 소유권, 미해결 항목, 출처, 해시 및 빌드
로그를 함께 기록한다. 불완전하거나 근거만 남은 결과는 해결된 코드와 구분한다.

실행 방법과 출력 구조는 [프로젝트 README](../README.md)에 정리되어 있다.

### 3.2 Kotlin/JVM 기반 정답 데이터 검증 경로

대규모 평가에서 에이전트의 추정 결과가 정답 데이터로 취급되지 않도록, Kotlin/JVM 검증 경로와
후보 코드 생성 경로를 분리하였다. 인증된 원본 ELF/DWARF, 범위 정의, 인벤토리, 함수 관측 및 함수
인덱스를 연결하고, 후보 JSON이 자체적으로 일관된 해시를 갖더라도 원본에서 유도한 사실과 다르면 거부한다.

전체 정답 데이터 체계의 Kotlin 전환은 아직 완료되지 않았다. 남아 있는 Python 경로와 실제 전체
트리 실행·릴리스 증거의 전환은 [이슈 #136](https://github.com/minsago-elite/decomp_thing/issues/136)에서 추적한다.

### 3.3 대규모 호출 관측 저장 및 배포 단위 구성

호출 관측은 전체 데이터를 메모리에 올리는 대신 SQLite에 저장하고 인덱스 순서대로 출력하도록 구성하였다.
레코드 크기, 항목 수, 데이터베이스 페이지, 캐시, 출력 크기 및 작업 시간을 별도로 제한한다.
전체 관측 실행에서는 인증된 인벤토리의 샤드 구성과 입력 해시를 확인하고, 각 샤드의 결과를 원본에서
다시 생성하여 검증한다. 중첩 검증이 상위 작업의 제한 시간을 새로 시작하지 않도록 하였다.

이 경로에는 기존 64 MiB 인메모리 출력 한계를 넘는 합성 관측 투영 회귀 테스트도 포함된다.
이는 제한된 저장·출력 경로의 검증이며, 실제 LLVM 전체 트리 실행 완료를 의미하지는 않는다.

### 3.4 교차 샤드 호출 관계 구성 및 독립 검증

`FullTreeCallTruthSqlite`는 원본에서 재검증한 함수와 호출 관측을 연결하여 정규화된 호출 관계 샤드와
통합 인덱스를 생성한다. 주요 검증 사항은 다음과 같다.

- 호출자와 대상 함수가 서로 다른 샤드에 있어도 인증된 함수 식별자로 연결한다.
- 함수 별칭, 직접 호출, 꼬리 호출, 물리적 thunk 대상, 외부 심볼 및 증명된 간접 호출 대상을 구분한다.
- 중복 관측은 결정적으로 합치고, 상충하는 관측·누락된 샤드·유효하지 않은 참조는 거부한다.
- 해석되지 않은 간접·가상 호출과 주소가 없는 관측은 불확실성을 유지하며 대상을 만들어내지 않는다.
- 결과는 읽기 전용 파일과 원자적 덮어쓰기 금지 방식으로 게시한다.
- 독립 검증은 원본에서 결과를 다시 유도하여 후보 트리의 구성과 바이트를 비교한다.

3개 샤드 테스트 자료에서는 관측 12건에서 호출 간선 11개를 얻었다. 샤드 간 순환 호출, 별칭,
물리적 thunk와 꼬리 호출, 외부 이름, 증명된 단일 콜백 대상, 미해결 간접·가상 호출을 검증하였다.
이 수치는 테스트 자료의 규모이지 실제 프로그램에 대한 복구 정확도 점수는 아니다.

구현 계약과 제한은 [호출 관계 구성 문서](full-tree-call-truth-kotlin.md)에 설명되어 있다.

### 3.5 원본 기반 호출 관측 기준선 생성·검증

`FullTreeCallBaselineSqlite`는 인증된 원본과 함수·호출 관계를 다시 검증한 뒤, 샤드별 관측 가능성
지표와 불일치 목록을 결정적인 보고서로 생성한다. SQLite 기반 집계와 스트리밍 출력으로 메모리·저장
공간·시간 제한을 유지하며, 후보 보고서의 해시를 다시 계산했더라도 원본에서 유도한 결과와 다르면 거부한다.

3개 샤드 테스트 자료의 중복 제거된 간선 11개는 평가 대상 9개와 제외 2개로 나뉜다. 평가 대상은
정확하게 관측된 관계 7개와 의미 대상이 미해결인 부분 관측 2개이다. 이는 정답 데이터의 관측 가능성
수치이며, 복구 모델과 비교한 정확도가 아니다. 실제 복구 모델을 입력받는 호출 관계 채점은 미구현이다.

보고서 형식은 기존 schema-v1을 유지하되 원본 검증 의미를 policy-v3으로 구분하였다. 게시 결과는
읽기 전용이며 기존 결과를 덮어쓰지 않는다. 원본 변경, 재해시한 위조 보고서, 비정상 링크·권한,
출력 경로 충돌, 자원 제한, 인터럽트 및 입력 검증 수명에 대한 회귀 테스트 10개를 추가하였다.

구현 계약과 제한은 [호출 관측 기준선 문서](full-tree-call-baseline-kotlin.md)에 설명되어 있다.

### 3.6 실행 환경 및 CI 안정성 개선

인증된 JDK 배치 경로, JNA 임시 파일 위치, systemd 사용자 버스 디렉터리 식별 및 기능 확인 과정의
실패 원인을 수정하였다. 테스트용 임시 디렉터리 정리에는 항목 수·총 크기·깊이 제한을 적용하였고,
심볼릭 링크·하드 링크·다른 마운트 및 알 수 없는 상위 잔여물을 임의로 삭제하지 않도록 하였다.

Docker 28.0.4의 `image inspect --platform` 미지원 문제는 동일 응답에서 이미지 ID와 플랫폼을
엄격하게 확인하는 방식으로 해결하였다. 빌드·실행 단계의 플랫폼 제한은 유지하였다.
인증된 Clang/LLD 실행 경로에는 이름 교체 공격을 확인하는 필수 회귀 검증도 추가하였다.
다만 실제 hosted worker 이미지에서 해당 실행 검증이 성공했다는 증거는 아직 확보하지 못하였다.

LLVM 도구 체인 이미지 빌드에는 Docker 클라이언트 호출당 15분 제한과 일반 실패 시 1회의 재시도를
추가하였다. 시간 초과·시그널 종료·실행기 오류는 재시도하지 않으며, 고정 Dockerfile·이미지·패키지·
인증 키·플랫폼과 성공 후 검증 절차는 변경하지 않았다. 이 제한은 Docker 클라이언트에 적용되는 것으로,
백그라운드 빌드 프로세스의 종료나 자원 회수가 증명되었다는 뜻은 아니다.

구현과 회귀 검증은 완료했지만 실제 hosted 환경의 이미지 빌드 성공은 추가 확인이 필요하다.
자세한 실패 기록과 정책은 [LLVM CI 빌드 문서](llvm-toolchain-ci-build.md)에 정리하였다.

## 4. 검증 결과와 증거

### 최종 관련 테스트

| 검증 영역 | 통과 |
|---|---:|
| 호출 관측 생성·샤드 게시·전체 실행 검증 | 40 |
| 호출 관측 형식 및 기존 의미 평가 | 8 |
| 3개 샤드 원본 ELF/DWARF 테스트 자료 | 3 |
| 새 호출 관계 구성·원본 기반 독립 검증 | 9 |
| 새 호출 관측 기준선 생성·원본 기반 독립 검증 | 10 |
| 함수 정답 데이터 및 함수 기준선 회귀 검증 | 8 |
| 제한된 임시 디렉터리 정리 | 6 |
| systemd 실패 로그 조회 인자 검증 | 1 |
| **합계** | **85** |

위 실행은 `721c2cb`의 검증 결과로 **실패 0건, 건너뜀 0건**이다.

재현 명령:

```bash
./gradlew test \
  --tests 'decompengine.oracle.fulltree.FullTreeCall*' \
  --tests decompengine.oracle.fulltree.FullTreeCrossShardCallFixtureTest \
  --tests decompengine.oracle.fulltree.FullTreeFunctionTruthSqliteTest \
  --tests decompengine.oracle.fulltree.FullTreeFunctionBaselineSqliteTest \
  --tests 'decompengine.oracle.fulltree.FullTreeFunctionObservationIsolatedFixtureRunnerTest.prepared fixture*' \
  --tests 'decompengine.oracle.gcc.GccCompilerEngineLiveContainmentControllerTest.live journal diagnostics request newest exact-unit events within existing bounds'
```

### LLVM CI 빌드 및 기존 검증 절차 회귀 테스트

`39aa80b`에서는 빌드 래퍼, 고정 재현 레시피, Kotlin 검증 권한 경계, 릴리스 자료, 생성 CLI 및
hosted worker 이미지 관련 테스트를 별도로 수행하였다. 결과는 **38건 중 36건 통과, 2건 생략,
실패 0건**이며, 셸 구문 검사도 통과하였다. 생략 사유는 로컬 LLVM 원본 자료 경로와 실제 Docker
실행 환경 설정의 부재이다. 이 결과를 실제 Docker 이미지 빌드·실행 성공으로 해석하지 않는다.

재현 명령:

```bash
bash -n scripts/ci-build-llvm-toolchain.sh
./gradlew test \
  --tests decompengine.oracle.provenance.LlvmToolchainBuildScriptTest \
  --tests decompengine.oracle.provenance.LlvmToolchainReproductionTest \
  --tests decompengine.oracle.fulltree.FullTreeKotlinAuthoritySurfaceTest \
  --tests decompengine.oracle.provenance.LlvmReleaseArtifactsTest \
  --tests decompengine.oracle.provenance.LlvmFunctionOracleGeneratorCliTest \
  --tests decompengine.oracle.behavior.LlvmBehaviorHostedWorkerImageLiveIntegrationTest
```

### 전체 CI 상태

이전 [CI 실행 `33936674771`](https://github.com/minsago-elite/decomp_thing/actions/runs/33936674771)의
Kotlin 작업은 총 1,311건 중 1,256건 통과, 29건 건너뜀, 26건 실패였다.
이 중 25건은 임시 디렉터리 정리 실패 1건과 이후 공유 ext4 슬롯 잔여물에 따른 연쇄 실패 24건이었다.

정리 수정과 최신 이벤트 우선 로그 수집을 포함한 `27feba3`의
[완료된 CI 실행 `33937775172`](https://github.com/minsago-elite/decomp_thing/actions/runs/33937775172)은
다음과 같다.

| 작업 | 결과 |
|---|---|
| `clang` | 성공 |
| `archival-ghidra` | 성공 |
| `kotlin` | 총 1,336건: 통과 1,303건, 생략 29건, 실패 4건 |

이 실행에서 기존 임시 디렉터리 정리 및 잔여물 연쇄 실패는 재발하지 않았다. 테스트 구성과 실행 수가
달라졌으므로 실패 건수 감소를 동일한 테스트 22개의 개별 수정 완료로 환산하지 않는다.
남은 실패는 다음 두 종류다.

- GCC 실행 경계 테스트 1건: systemd journal에서 scope의 실행 시간 제한 초과 종료를 확인하였다.
  해당 테스트의 명시적 실행 예산과 실제 소요 시간의 조정·재검증은 아직 완료하지 않았다.
- 전체 트리 실행·복구 테스트 3건: BOOT 확인 전에 systemd scope가 종료되었다.
  정확한 종료 원인은 추가 진단이 필요하며, GCC와 동일한 원인이라고 단정하지 않는다.

보고서 구현 기준인 `39aa80b`의 [CI](https://github.com/minsago-elite/decomp_thing/actions/runs/33939594043),
[LLVM oracle](https://github.com/minsago-elite/decomp_thing/actions/runs/33939594046),
[GCC oracle](https://github.com/minsago-elite/decomp_thing/actions/runs/33939594040)는 상태 확인 시점에 대기 중이다.
따라서 **관련 단위·통합 테스트 통과와 전체 CI 통과를 구분**하며, 완료된 이전 커밋의 CI 결과를
최신 커밋의 검증 결과로 대체하지 않는다.

### 주요 코드 체크포인트

| 커밋 | 주요 내용 |
|---|---|
| `972cdd3` | 제한된 SQLite 기반 Kotlin 호출 관측 저장 |
| `2be06bd` | 원본 기반 전체 호출 관측 실행 게시·검증 |
| `d45b66f` | BOOT 임시 파일·systemd 엔드포인트 및 기능 확인 수정 |
| `83ffcc4`, `7e0b049` | 3개 샤드 원본 테스트 자료 및 thunk ABI 정합성 |
| `6db803d` | Docker 28 호환 이미지 ID·플랫폼 검증 |
| `c643b15` | 중첩 호출 관측 검증의 상위 제한 시간 유지 |
| `e27e162` | 원본 기반 교차 샤드 호출 관계 구성·독립 검증 |
| `27feba3` | 제한된 임시 파일 정리 및 최신 실패 이벤트 수집 |
| `721c2cb` | 원본 기반 호출 관측 기준선 생성·독립 검증 |
| `39aa80b` | 고정 LLVM 빌드 조건을 유지한 CI 시간 제한·제한적 재시도 |

## 5. 미완료 항목 및 해석상 제한

- GCC 드라이버 대상 성과를 GCC 컴파일러 엔진 전체의 재구성 완료로 확대 해석하지 않는다.
- 작은 원본 테스트 자료의 성공을 Clang/LLVM 전체 트리 정확도·동작 동등성의 증거로 사용하지 않는다.
- 원본 기반 호출 관측 기준선은 구현했지만, 복구 모델의 exact/partial/missing/fabricated 채점은 아직 미구현이다.
- relocation에 연결된 PLT 대상, 정규화된 thunk 의미 대상, 가상 호출 슬롯·증명된 가상 대상 집합은 추가 작업이 필요하다.
- Kotlin-only 정답 데이터 체계 전체 전환, 전체 샤드의 격리 실행·복구 증거 및 최종 릴리스 승인 경로는 진행 중이다.
- 현재 호출 관계 결과의 릴리스·후속 채점 승인 플래그는 명시적으로 `false`이다.
- 미검증 개발 초안은 본 보고서의 구현 완료 성과 및 테스트 수치에 포함하지 않았다.

## 6. 이후 A-series 개발 방향

A10에서는 GCC 컴파일러 엔진의 실행·복구 경계를, A13에서는 호출 위치를 보존하는 복구 결과 입력과 실제 채점,
추가 대상 증거 및 규모 검증을 계속 진행한다. A14의 전체 소스 트리 재구성과 A15의 동작 검증은
해당 정답 데이터·실행 경계의 증거를 연결하여 단계적으로 검증한다.

실제 작업 범위와 완료 판단은 [GitHub 이슈](https://github.com/minsago-elite/decomp_thing/issues) 및
마일스톤을 기준으로 관리한다. 본 문서는 제출을 위한 날짜 고정 현황 보고서이며, 실시간 계획 목록을 대체하지 않는다.
