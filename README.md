# PENTAX K-3 II v1.12 펌웨어 분석

[최신 Pixel Shift·버퍼 수명 보고서](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/superresolution-lifecycle.html) · [마스크 CPP·모드 보고서](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/masked-cpp-analysis.html) · [백엔드 B·CPP 보고서](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/backend-b-cpp-analysis.html) · [SD·대체 버퍼 보고서](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/storage-dma-analysis.html) · [버퍼·메뉴 보고서](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/output-menu-analysis.html) · [톤·색 처리 보고서](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/pipeline-analysis.html) · [심층 분석 보고서](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/deep-analysis.html) · [초기 분석](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/) · [최신 보고서 소스](analysis/superresolution-lifecycle.html)

2026-11-08 Pixel Shift·버퍼 수명 후속: 실제 Pixel Shift Resolution 메뉴의 On/Off→활성 프로필 설정→SuperResolution 종류 11을 연결했습니다. RAW MakerNote의 같은 번호 태그는 별도 저장소임을 검증했습니다. 슬롯 4·17의 할당·해제·재할당과 일반 출력→스케일러→JPEG 디스크립터 연결을 재현했습니다. 공통 스케일러 설정부터 큐 호출 지점까지의 64개 합성 사례는 모두 활성값 0이었으며, 비영 생산자와 실기 촬영별 주소 이력은 미확정입니다.

2026-11-08 마스크 CPP 후속: 보조 스케일러 두 출력과 JPEG 보조 입력의 조건부 평면 주소 공유, 모듈 20 출력→후속 CPP 입력을 검증했습니다. Color Fringe Correction 메뉴값→태그 0x245→작업 종류 5의 두 번째 패스도 연결했습니다. 네 작업의 배치 구분값 생산자와 SuperResolution 종류 11 호출을 확인했습니다. 당시 남았던 할당·재사용 규칙은 최신 보고서에서 후속 검증했습니다. 비영 활성값의 생산자와 실기 촬영 이력은 미확정입니다.

2026-11-08 백엔드 B·CPP 후속: B의 파일 쓰기를 SD 명령·ADMA 설정까지 연결했습니다. 두 번째 CPP 출력은 모듈 17 합성 입력으로 전달되며, 기본 분기에서 합성 목적지→스케일러 입력과 스케일러 출력→JPEG 입력의 주소 일치를 확인했습니다. B 실행 7건, 레시피 4개, 버퍼 전달 4건과 보조 스케일러 gate를 검증했습니다. 마스크 분기의 이후 연결과 물리 픽셀 처리·SD 기록은 미확정입니다.

2026-11-08 저장 경로 후속: 백엔드 A의 전체·부분 섹터 버퍼를 카드 객체와 연결하고, 두 SD 포트의 CMD24·CMD25, ADMA2 표, 완료·오류 처리를 검증했습니다. CSD 용량 단위, 16 MiB 단위 재분할, CPP 대체 평면과 JPEG 공유·재시도 조건도 확인했습니다. 원본 명령 합성 사례 49건을 재현했으며 당시 남았던 백엔드 B 하위 경로는 최신 보고서에서 검증했습니다. 실제 SD 기록은 미검증입니다.

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
python verify_filesystem_backend.py .private/decoded/decoded.bin --compare analysis/filesystem-backend.json
python verify_sd_controller.py .private/decoded/decoded.bin --emulate --compare analysis/sd-controller.json
python verify_alternate_buffers.py .private/decoded/decoded.bin --compare analysis/alternate-buffers.json
python verify_backend_b.py .private/decoded/decoded.bin --compare analysis/backend-b.json
python verify_cpp_handoff.py .private/decoded/decoded.bin --compare analysis/cpp-handoff.json
python verify_masked_scaler.py .private/decoded/decoded.bin --compare analysis/masked-scaler.json
python verify_mode_reachability.py .private/decoded/decoded.bin --compare analysis/mode-reachability.json
python verify_superresolution_menu.py .private/decoded/decoded.bin --emulate --compare analysis/superresolution-menu.json
python verify_buffer_history.py .private/decoded/decoded.bin --compare analysis/buffer-history.json
python verify_scaler_gate.py .private/decoded/decoded.bin --compare analysis/scaler-gate.json
python -m unittest discover -s tests -v
python verify_publication.py
```

분석 도구는 GPL-2.0으로 배포합니다. 난독화 알고리즘 출처와 공개 범위는 [HTML 보고서](index.html#sources)에 정리했습니다. 제조사 펌웨어에는 이 저장소의 라이선스가 적용되지 않습니다.
