# 01 / K-3 II RAW 노이즈 감소 — 펌웨어 수정 가능성

검토일: 2026-11-13. 대상: K-3 II 펌웨어 **1.12**, `fwdc230b.bin`.

**판정: LNR 제어 코드의 조사 출발점 확보. 저장 RAW의 NR On/Off 패치는 미확정.**

K-3 Mark III와의 비교·알고리즘 후보·촬영 조건·공통 후속 과제는 [통합 검토 문서](https://github.com/yunhyok/pentax-k3iii-firmware-analysis/blob/main/docs/research/RAW_NR_FEASIBILITY_20261113_KO.md)에 정리.

## 02 / 측정 근거 — 첫 NR 표시는 ISO 1600

[Photons to Photos 원본 측정](https://www.photonstophotos.net/Charts/PDR.htm#Pentax%20K-3%20II,Pentax%20K-3%20III)에서 K-3 II의 첫 NR 표시는 **ISO 1600**. ISO 100–1250에는 표시 없음. K-3 III 컬러의 ISO 200과 구분할 것. 표시가 없다고 모든 RAW 전처리가 없다는 뜻은 아님. 기고 RAW의 측정 결과이며 이번 1.12 펌웨어의 실측 결과는 아님.

[설명서 인쇄 p.42](https://www.ricoh-imaging.co.jp/english/support/man-pdf/k-3-2.pdf#page=46)의 High-ISO NR에는 Off 존재. 인쇄 p.39의 장노출 NR은 별도 설정. [공식 FAQ](https://www.ricoh-imaging.co.jp/english/support/qa/k-3-2/index.html)는 고감도에서 메뉴 NR 상태와 별개로 기본 영상 처리 시간이 늘 수 있다고 설명. 다만 구체적인 RAW 필터 수식이나 ISO 1600 역치를 공식적으로 명시한 것은 아님.

따라서 조사 대상은 **메뉴 Off 이후에도 저장 RAW에 남는 처리**. K-3 III의 가속기 설명이나 NR 함수 이름을 K-3 II의 구현 증거로 사용하지 않을 것.

## 03 / 이번 정적 확인 — LNR 레지스터 진단 경로

공식 [1.12 배포본](https://www.ricoh-imaging.co.jp/english/support/digital/k3_2.html)을 받아 기존 `inspect_firmware.py`로 해제. 기존 근거의 SHA-256과 일치. 아래 주소는 후보 코드 베이스 `0x02000000`을 적용한 분석 주소. 실기 레지스터를 읽거나 쓴 결과가 아님.

| 지점 | 확인 내용 | 의미의 한계 |
|---|---|---|
| `0x024c6b9c` 주변 | LNR 레지스터 출력 함수 | 일반 촬영에서 실행되는 NR 자체가 아님 |
| `0x024c6ba8` | 리터럴에서 레지스터 베이스 `0x20000000` 적재 | 실제 칩의 모든 기능 정의를 확보한 것은 아님 |
| `0x024c6bb8` | 위 베이스 `+0x304` 값을 읽음 | 읽는 코드 확인. 실기 읽기·값 관측 미수행 |
| `0x024c6bbc` | `LNRCTL` 출력 문자열 주소 구성 | 제어 비트별 의미·Off 값은 미확정 |
| `0x024c6bc0` | 출력 함수 `0x027073ec` 호출 | NR 알고리즘 실행 호출이 아님 |
| 주변 문자열 | `LNRTRG`, `LNRCTL`, `LNRXTH`, `LNR0T0/1`, `LNR1T0/1` | 명칭상 NR 블록 조사 후보. 저장 RAW 적용 증거는 아님 |

`LNR` 약어를 특정 필터 수식으로 확대 해석하지 않을 것. 위 블록이 JPEG 현상 전용이면 저장 RAW의 강제 NR 해제에는 효과가 없을 수 있음. **가장 먼저 필요한 작업은 해당 제어값의 쓰기 함수와 PEF/DNG 저장 분기의 연결 확인.**

이번 검증 결과: [nr-candidates.json](../../analysis/nr-candidates.json). 기존 전체 영상 처리 흐름: [영상 처리 안내](../../analysis/guide-pipeline.html). 기존 분석 기준 커밋: `ed0f6f0ff0fddd91f25068efbe940d035a809598`.

## 04 / 수정 가능성과 다음 관문

| 질문 | 현재 판단 |
|---|---|
| 파일을 풀고 다시 만들 수 있는가 | 기존 난독화 해제·재포장 도구 및 무변경 일치 근거 존재 |
| NR 제어 후보가 있는가 | LNR 진단 경로 확보. 실제 RAW 필터인지는 미확정 |
| 메뉴 Off와 연동되는가 | 미확정. 메뉴값 생산자·레지스터 쓰기 경로 추적 필요 |
| 지금 설치할 수정본이 있는가 | 없음. NR 패치 생성·플래시·부팅 시험 미수행 |

[기존 repack 근거](../../analysis/repack.json)의 가산 체크섬·마커 검증은 카메라의 전체 인증이나 정상 부팅을 입증하지 않음. 조건 없이 제어 레지스터를 0으로 만들면 관련 처리·버퍼·완료 순서가 함께 깨질 수 있으므로, 비트 의미와 처리 의존성을 먼저 확인할 것.

1. **NR-II-01 / 기준 RAW 확보.** ISO 100·800·1250·1600·2000의 짧은 암프레임·평탄광 반복 촬영. High-ISO NR과 장노출 NR Off, Pixel Shift·HDR·다중 노출·AA 시뮬레이터 미사용. 정확한 펌웨어·촬영 조건 기록.
2. **NR-II-02 / LNR 쓰기 경로 추적.** `0x20000304`에 해당하는 제어값 생산자와 설정 구조체 추적. 단순 문자열·레지스터 이름 일치로 종료하지 않을 것.
3. **NR-II-03 / RAW와 JPEG 분리.** RAW 저장 버퍼가 LNR 처리 전후 중 어디서 나오는지 확인. 미일치 시 센서 전처리·불량 화소 보정·별도 ISP 블록으로 조사 범위 전환.
4. **NR-II-04 / 최소 우회 검증.** 적용 블록 확인 후 처리만 우회하고 버퍼·완료 통지는 유지. On에서 기존 동작 복원, Off에서 CFA 공간 통계 변화 확인. 이 단계 전에는 실기 패치 적용을 진행하지 않음.

실험 방법과 필터 후보별 판별 기준은 [통합 문서의 03·06절](https://github.com/yunhyok/pentax-k3iii-firmware-analysis/blob/main/docs/research/RAW_NR_FEASIBILITY_20261113_KO.md) 참조.

## 05 / 재현 방법

원본·해제 파일은 이 저장소에 포함하지 않음. 해제는 기존 도구 사용.

```powershell
python inspect_firmware.py fwdc230b.bin --output-dir .private/nr-decode
```

중복 도구를 만들지 않기 위해 NR 후보 검증기는 K-3 III 저장소의 [verify_nr_candidates.py](https://github.com/yunhyok/pentax-k3iii-firmware-analysis/blob/main/verify_nr_candidates.py)에 통합. 두 저장소를 같은 상위 폴더에 복제했을 때 K-3 III 저장소에서 실행할 것.

```powershell
python verify_nr_candidates.py k3ii ../pentax-k3ii-firmware-analysis/.private/nr-decode/decoded.bin --compare ../pentax-k3ii-firmware-analysis/analysis/nr-candidates.json
```

| 파일 | SHA-256 |
|---|---|
| 원본 | `a33485f351019960192891ef69ddc5d4904ef9e298671d9d9955679e4c901a9a` |
| 해제본 | `1b87bf35b290e4b4e8910beb4055c34f97504b65e249ad65e5ccc0402bd14cfc` |

공개 측정의 원문 해시·판독 절차: [raw-nr-public-evidence.json](https://github.com/yunhyok/pentax-k3iii-firmware-analysis/blob/main/analysis/raw-nr-public-evidence.json). 이번 결과는 원본 바이너리의 정적 확인이며 실기 NR 해제 성공 보고가 아님.
