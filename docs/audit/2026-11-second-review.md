# 2026년 11월 2차 검수 기록 — K-3 II (v0.4.0)

v0.3.0과 v0.3.1에서 새 문서가 올라온 뒤, 그 문서들을 검수하고 사이트 전체의 문장을 다시 다듬었습니다. 이 문서는 그 결과입니다. 1차 기록은 [2026-11-review.md](2026-11-review.md)에 있습니다.

## 무엇을 했나

| 대상 | 한 일 |
|---|---|
| v0.3.x에서 새로 올라온 문서 8쪽 (톤 6쪽, `preserved-continuity`, `register-dma`) | 근거 JSON·검증기·테스트와 대조한 뒤, 다른 문서와 같은 형식(요약 → 확인한 범위 → 배경 → 본문 → 한계 → 재현 → 출처)으로 다시 쓰고 그림을 넣었습니다 |
| Markdown 메모 `docs/research/RAW_NR_FEASIBILITY_20261113_KO.md` | 검수해 사이트 문서 `analysis/raw-nr-feasibility.html`로 옮겼습니다. 메모 파일에는 안내 문구와 링크만 남겼습니다 |
| 내용이 덧붙은 `preserved-config.html` | 덧붙은 부분을 근거와 대조하고 문서 구조에 맞춰 넣었습니다 |
| 안내 문서 `guide-pipeline`, `guide-capture` | 새 문서를 지도·표·읽는 순서에 넣었습니다 |
| 기존 문서 30쪽 | 내용은 그대로 두고 문장만 다듬었습니다 |

모두 42쪽이고 그림은 109개입니다.

### 한계

이번에도 원본 펌웨어 없이 검수했습니다. 문서가 공개된 근거 JSON·검증기와 맞는지 확인했고, 검증기를 펌웨어에 다시 돌리지는 않았습니다. 펌웨어 없이 도는 검사(`verify_publication.py`, 단위 시험 101개)는 통과했습니다.

## 고친 내용

수치·주소·해시는 근거와 모두 맞았습니다. 고친 것은 아래와 같습니다.

| 문서 | 원래 내용 | 고친 내용 | 근거 |
|---|---|---|---|
| `preserved-config.html` | 그림이 "+0xD 마커 재검사"를 정적 분석으로 표시 | 연결 실험에서 실행으로 확인한 항목으로 표시 | `preserved-marker-checks.json`의 `connected_cases[*].marker_controls` (둘째 마커가 틀린 사례에서 이웃 getter가 0을 돌려주고 `+0xD` 읽기가 기록됨) |
| `preserved-continuity.html` | 표의 열 이름 "명령 콜백 526/505/512" | "실행한 명령 수" | 근거 JSON의 `instruction_widths` |
| `raw-nr-feasibility.html` (옛 메모) | 사용설명서 High-ISO NR 링크가 PDF 46쪽(초점 설정 화면)을 가리킴 | PDF 44쪽 (인쇄된 42쪽) | 리코 K-3 II 사용설명서. 인쇄 쪽 번호에 2를 더하면 PDF 쪽 번호입니다 |
| `tone-provenance.html` | 이미 있던 정정(참조 슬롯은 `job+26C0`, 예전 표기 `job+225C`)이 문단 속에 묻혀 있음 | 정정 상자로 드러냄 | `tone-provenance-contract.json`의 erratum |
| `index.html` | Lightroom 색 비교가 "사진 한 장뿐"이라는 서술 | 현재 상태(독립 장면 한 장 추가, 사전 기준 일부 미충족)로 갱신 | K-3 Mark III 저장소의 `lightroom-composed-tone.html` |
| 사이트 지도 | `register-dma`의 이름 "보정 결과 레지스터…" | "검출 결과 레지스터와 DMA 준비" | 문서 제목과 검증기의 이름(PixelDetect) |
| 새 문서 여러 곳 | "~다"체와 합쇼체가 섞임, 페이지 전용 CSS, PowerShell 전용 명령 | 합쇼체, 공용 스타일, 일반 명령으로 통일 | 문서 형식 규칙 |

1차 기록의 "판단이 필요한 항목"에 있던 "`preserved-config.html`의 `+0xD` 재확인은 워드 비교뿐"이라는 항목은 이제 해당하지 않습니다. 위 연결 실험이 실행 근거입니다.

## 문장 다듬기

한국어 윤문 규칙(humanize-korean)을 적용했습니다. 내용 명사·수치·코드는 그대로 두고 문형만 고치는 방식입니다.

- 연결어미 바로 뒤의 쉼표("~하고, ~")를 뺐습니다. 기존 문서에서 408곳입니다.
- 문단 205개를 고쳐 썼습니다. 긴 문장을 나누고, "A가 아니라 B입니다" 식 대구와 "~라는 뜻입니다" 식 종결을 직접 서술로 바꿨습니다. 고친 문단마다 태그, 숫자·주소·영문 식별자, 코드가 원문과 같은지 기계로 확인한 뒤 반영했습니다.
- 목록의 "라벨 — 설명"에 쓴 대시 68개를 쌍점이나 마침표로 바꿨습니다.

| 지표 (본문 산문 기준) | 이전 | 이후 |
|---|---|---|
| 연결어미 뒤 쉼표 | 487 | 0 |
| 90자를 넘는 문장 | 49 | 16 |
| "~라는 뜻입니다" 류 종결 | 14 | 1 |
| "A가 아니라 B" 류 대구 | 44 | 12 |
| 설명을 잇는 대시 | 208 | 1 |

남은 대구 12개는 오해를 바로잡는 문장이라 그대로 두었습니다(예: "잠금이 아니라 상태 사본"). 개편 전 문서에 있던 16진수 주소와 해시는 새 문서에 모두 남아 있습니다.

## 판단이 필요한 항목

**용어가 겹치는 곳**

- 톤 문서의 "recipe"는 `job+E0C4`에 있는 톤 설정 객체입니다. `pipeline-analysis.html`과 용어집의 "레시피"(모듈 호출 순서)와는 다른 대상입니다. 톤 문서에서는 "recipe 객체"로 적고 차이를 풀이했습니다.
- "selector"가 세 가지 뜻으로 쓰입니다. 처리 단계 번호(3·4), 톤 선택값(6), setter의 항목 번호(5·6·0x1E·0x2B)입니다. setter의 selector 6과 톤 선택값 6(Reversal Film)이 같은 것이라는 근거는 없습니다. 안내 문서에 그렇게 적었습니다.

**개편 전 문서에만 있고 근거 JSON에서 찾지 못한 것** (원문대로 두었습니다)

- `tone-upstream.html`: "관리자 `+0x1C`가 0일 때 리더가 그 자리에 인덱스|0x8000을 잠시 기록".
- `register-dma.html`: NRDNCNT·NRDNSIZE·NRDNLIMIT, PixelDetect라는 이름은 검증기 안에만 있습니다. 펌웨어 문자열에서 왔는지 확인하지 못해 "검증기가 적는 이름"으로 적었습니다.

**이번에 새로 넣은 계산·연결** (본문에 한정해 적었습니다. 원 연구 범위만 남기려면 해당 문단을 지우면 됩니다.)

- `register-dma.html`: 기본 DMA 버퍼 두 주소가 ID 0x64 RAM 사본에서 디스크립터 24·25의 데이터 자리와 같다는 계산. 전송 길이·방향·재사용을 보여 주는 것은 아닙니다.
- `tone-scale.html`: `job+6D`가 `tone-inputs.html`의 코드가 읽는 필드와 같은 오프셋이라는 연결. 두 시험은 따로 실행했습니다.

**그 밖에**

- `tone-upstream.html`의 최종 R5는 단순한 곱(ROM 값 × 계수 ÷ 8192)으로 나오지 않습니다(예: 16384 × 8211 ÷ 8192 = 16422인데 기록은 16416). 그래서 식을 적지 않았습니다.
- `tone-selectors.json`의 `manager_flow`에는 세 번째 갱신 호출이 있습니다. 이것이 `tone-manager.html`이 분석하지 않은 후보 25개에 드는지는 알 수 없습니다.
- 이미 게시한 릴리스 노트 `docs/releases/v0.3.0.md`는 DMA 인자 준비의 근거로 `storage-dma-analysis.html`을 링크합니다. 그 근거는 `register-dma.html`이며, 저장 경로가 아니라 검출 결과 레코드의 버퍼입니다. 게시된 노트는 고치지 않았습니다.

## 근거 JSON·스크립트에서 발견한 문제

손대지 않았습니다. 결과에 영향을 주는 것은 없습니다.

| 파일 | 문제 |
|---|---|
| `analysis/tone-provenance-contract.json` | `files[]`에 `analysis/tone-provenance.html`의 크기·해시와 `assets/tone-provenance.css`가 적혀 있습니다. 문서를 다시 써서 해시가 달라졌고, 새 문서는 그 CSS를 쓰지 않습니다. CSS 파일은 남겨 두었습니다. 테스트는 이 해시를 검사하지 않습니다 |
| `analysis/hq-status.json` | `goals[1].gaps[0]`의 "No measured K-3 II RAW/JPEG pairs or Lightroom pixel comparison."은 이후 측정으로 낡았습니다 |

## Lightroom 색 프로파일에 대한 판정

이번 릴리스에 카메라 색 프로파일을 넣지 않았습니다. K-3 II용 후보는 하나 있지만(차트 한 장의 무채색 패치로 맞춘 톤 곡선), 배포할 수준이 아닙니다.

- 맞춘 차트에서도 Adobe가 Lightroom에 넣어 둔 Camera Natural 프로파일이 카메라 JPEG에 더 가깝습니다(패치 24개 평균 ΔE00: 후보 1.786, Camera Natural 1.620). 따로 찍은 장면에서도 같습니다(4.057 대 3.948).
- 후보는 미리 정한 허용값 가운데 하나를 넘겼습니다(주황 패치 0.892, 허용값 0.75).
- 시험한 조명은 하나이고, 표본은 펌웨어 1.10으로 찍은 것입니다(분석 대상은 1.12).

수치의 출처와 세 기종의 비교는 K-3 Mark III 저장소의 [Lightroom 색 프로파일 안내](https://yunhyok.github.io/pentax-k3iii-firmware-analysis/analysis/guide-lightroom.html)에 있습니다.

## 외부 자료로 확인한 사실 (요약)

- 펌웨어 1.12는 2021-07-20 배포, `k3ll_v112.zip` (리코 다운로드 페이지).
- Photons to Photos의 PDR 도표에서 K-3 II에 노이즈 감소 표시가 처음 나타나는 감도는 ISO 1600입니다(ISO 100~1250에는 없음). 내려받은 도표 페이지의 SHA-256이 근거 파일의 기록과 같습니다.
- 사용설명서: High-ISO NR에 Off가 있고 Slow Shutter Speed NR은 별도 항목입니다. 리코 FAQ는 고감도 구간에서 노이즈 감소 설정과 무관하게 처리 시간이 늘 수 있다고 설명합니다.
- MMIO와 DMA의 일반 설명(Linux 커널 문서), BLX 명령의 Thumb 전환(Arm), AAPCS32의 인수 레지스터.
