# PENTAX K-3 II v1.12 펌웨어 분석

[심층 분석 보고서](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/deep-analysis.html) · [초기 분석](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/) · [보고서 소스](analysis/deep-analysis.html)

2026-11-08: F²MC-8L 호환 보조 코드, 추가 ARM 시작 경로, RAW 현상 함수와 톤 곡선 생성·B2Y 설정을 추적했습니다. 원본 명령 실행으로 곡선 출력 268,288개와 적용 함수의 두 합성 사례를 대조했습니다. 정확한 SoC·MCU 부품 번호와 전체 픽셀 처리 순서는 미확정입니다.

K-3 II의 `fwdc230b.bin`을 식별하고 XOR 난독화 해제, 코드·주소 검증을 진행하는 연구 저장소입니다. K-3 Mark III의 조사 절차를 따르되 칩, 명령어, 주소, 영상처리 구조는 별도로 검증합니다.

문서는 HTML을 기본으로 합니다. 저장소를 내려받아 `index.html`을 열면 도식과 근거 표를 오프라인으로 읽을 수 있습니다. 원본 펌웨어·해제 바이너리·디스어셈블 결과는 공개하지 않습니다.

```powershell
python inspect_firmware.py <fwdc230b.bin 경로> --output-dir .private/decoded
python verify_findings.py .private/decoded/decoded.bin
python verify_hardware.py .private/decoded/decoded.bin --compare analysis/hardware.json
python verify_raw_path.py .private/decoded/decoded.bin --compare analysis/raw-path.json
python verify_tone_path.py .private/decoded/decoded.bin --compare analysis/tone-path.json
python -m unittest discover -s tests -v
```

분석 도구는 GPL-2.0으로 배포합니다. 난독화 알고리즘 출처와 공개 범위는 [HTML 보고서](index.html#sources)에 정리했습니다. 제조사 펌웨어에는 이 저장소의 라이선스가 적용되지 않습니다.
