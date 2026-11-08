# PENTAX K-3 II v1.12 펌웨어 분석

[최신 버퍼·메뉴 보고서](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/output-menu-analysis.html) · [톤·색 처리 보고서](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/pipeline-analysis.html) · [심층 분석 보고서](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/deep-analysis.html) · [초기 분석](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/) · [최신 보고서 소스](analysis/output-menu-analysis.html)

2026-11-08 버퍼·메뉴 후속: B2Y→스케일러→JPEG 모듈 16→StoreImage의 조건부 버퍼 경로와 Exif 헤더·압축 데이터의 파일시스템 전달을 연결했습니다. 실제 화면 이벤트 `0x01205010`과 Reversal Film 문자열 리소스가 selector=6으로 이어집니다. 원본 명령으로 검증했으며 실기 JPEG 생성·SD 기록은 수행하지 않았습니다.

2026-11-08 톤·색 처리: RAW 작업 전달과 톤·저장 분기, selector=6 → ImageTone=7(Reversal Film), WB·색 행렬·클리핑을 추가 분석했습니다. 이 단계에서 남았던 화면 이벤트와 버퍼 연결은 최신 보고서에서 후속 검증했습니다. 물리 ISP 동작은 미검증입니다.

2026-11-08 1차: F²MC-8L 호환 보조 코드, 추가 ARM 시작 경로, RAW 현상 함수와 톤 곡선 생성·B2Y 설정을 추적했습니다. 원본 명령 실행으로 곡선 출력 268,288개와 적용 함수의 두 합성 사례를 대조했습니다. 정확한 SoC·MCU 부품 번호와 전체 픽셀 처리 순서는 미확정입니다.

K-3 II의 `fwdc230b.bin`을 식별하고 XOR 난독화 해제, 코드·주소 검증을 진행하는 연구 저장소입니다. K-3 Mark III의 조사 절차를 따르되 칩, 명령어, 주소, 영상처리 구조는 별도로 검증합니다.

문서는 HTML을 기본으로 합니다. 저장소를 내려받아 `index.html`을 열면 도식과 근거 표를 오프라인으로 읽을 수 있습니다. 원본 펌웨어·해제 바이너리·디스어셈블 결과는 공개하지 않습니다.

수치 검증에는 Unicorn 2.1.4가 필요합니다. 별도 Python 환경에서 `python -m pip install unicorn==2.1.4`로 설치할 수 있습니다.

```powershell
python inspect_firmware.py <fwdc230b.bin 경로> --output-dir .private/decoded
python verify_findings.py .private/decoded/decoded.bin
python verify_hardware.py .private/decoded/decoded.bin --compare analysis/hardware.json
python verify_raw_path.py .private/decoded/decoded.bin --compare analysis/raw-path.json
python verify_tone_path.py .private/decoded/decoded.bin --compare analysis/tone-path.json
python verify_pipeline_flow.py .private/decoded/decoded.bin --compare analysis/pipeline-flow.json
python verify_selector_path.py .private/decoded/decoded.bin --emulate --compare analysis/selector-path.json
python verify_isp_paths.py .private/decoded/decoded.bin --compare analysis/isp-paths.json
python verify_isp_numeric.py .private/decoded/decoded.bin --compare analysis/isp-numeric.json
python verify_jpeg_buffers.py .private/decoded/decoded.bin --compare analysis/jpeg-buffers.json
python verify_menu_events.py .private/decoded/decoded.bin --emulate --compare analysis/menu-events.json
python verify_exif_output.py .private/decoded/decoded.bin --compare analysis/exif-output.json
python -m unittest discover -s tests -v
python verify_publication.py
```

분석 도구는 GPL-2.0으로 배포합니다. 난독화 알고리즘 출처와 공개 범위는 [HTML 보고서](index.html#sources)에 정리했습니다. 제조사 펌웨어에는 이 저장소의 라이선스가 적용되지 않습니다.
