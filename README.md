# PENTAX K-3 II v1.12 펌웨어 분석

[촬영 준비의 연속 호출](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/capture-prepare.html): 원본 아홉 호출을 거쳐 정책 입력을 생산하는 21건과 앞부분 분기 21건을 실행 대체 없이 검증했습니다. 별도 세 사례는 준비 함수의 실제 반환까지 실행해 이미지 포인터 보존과 원본 생산자가 연결한 내장 레코드 여섯 개의 메타데이터 초기화를 대조했습니다. 실제 촬영 작업은 미검증입니다.

[픽셀 보정 활성값과 작업 준비 분기](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/pixel-policy.html): 원본 정책 53건, 조회표 364개 셀과 경계 21건, 준비 분기 12건을 검증했습니다. 정책→패킷→같은 버퍼의 보정을 연결했으며, 종류 11의 준비 분기가 정책 호출 블록을 건너뛰는 조건을 구분했습니다.

[보존 픽셀 레코드와 촬영 패킷](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/pixel-records.html): 섹터 15~19의 공급자 10개를 원본 픽셀 보정과 연결했습니다. 같은 버퍼의 순차 수정, 적재 캐시와 재적재 경계, 패킷 활성 0/1 및 섹터 저장 요청 18개를 검증했습니다. 별도 [좌표 경계 여섯 대조](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/pixel-records.html#coordinate-boundary)는 중심 검사와 이웃 주소 검사를 구분합니다. 실제 촬영 도달과 물리 기록은 미검증입니다.

[보존 섹터 14의 진단 레코드](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/preserved-record.html): 등록 ID 0의 32바이트 적재, 애플리케이션 사본, SerialNo(UID) 진단 인수와 섹터 저장 요청을 연결했습니다. 실제 장치 식별값·사본의 역전달·물리 기록은 미검증입니다.

[색공간 메뉴 알림과 화면 전환](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/ui-dispatch.html): 공유 상태의 키 0x1D, 필터 캐시, 대기·활성 레코드와 원본 전환 함수를 연결했습니다. 대상 0xB4의 0xE8바이트 할당 요청까지 재현했으며, 실제 버튼·RTOS 전달·화면 생성 완료는 미검증입니다.

[AF 카운터·보정값 생산자](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/af-input.html): 타이머·UDC 생성자와 실제 레지스터 주소를 연결하고 보정값 분기 14건·후속 계산 12건을 원본 ARM으로 재현했습니다. 같은 객체의 요청 367·40이 구동 준비 입구까지 전달됐습니다. 두 시점의 카운터 변화와 물리 구동은 미검증입니다.

[톤 보간 함수의 C 재구현](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/tone-rebuild.html): 원본 64바이트 함수와 같은 크기의 Cortex-A9 A32 코드를 만들고, 에뮬레이터에서 원본 호출 2,304회·출력 2,048개와 수치 출력 268,288개를 대조했습니다. 지정한 빌드는 원본 호출자가 요구하는 r3·r12를 보존합니다. 조건 플래그는 달라지는 반례가 있으며 확인된 호출 루프는 자체 비교로 이를 다시 설정합니다. 설치 파일 생성·물리 설치는 하지 않았습니다.

[색 공간 메뉴·표시](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/color-ui.html) · [보존 섹터·설정 저장](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/settings-storage.html)

2026-11-08 색 공간 후속: sRGB=0·AdobeRGB=1, 설정 0x15C의 선택·확정·취소·재열기 8건을 검증했습니다. 같은 값 확정도 RAM 두 위치에 기록하지만 별도 저장 함수는 동일 섹터의 쓰기 요청을 생략합니다. 설정 복사본 선택과 반대 섹터 요청 29건을 재현했으며, 메타데이터와 주 설정의 선택값이 다를 수 있음을 확인했습니다. 물리 버튼·LCD·플래시 기록은 미검증입니다.

[업데이트 전송·기록 오류](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/installation.html) · [RAW 형식 메뉴·텍스트 ABI](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/ui-resources.html)

[AF 요청 계산·구동 준비](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/af-control.html): 능력 조회 조건과 같은 객체의 요청값 생산·소비를 원본 ARM 25건으로 검증했습니다. 바디·렌즈 구동 준비 분기까지 실행했으며 센서 입력 생성·호출 사이의 스케줄링·물리 구동은 미검증입니다.

2026-11-08 설치 경로 후속: 보조 이미지의 64바이트 전송·전체 다시 읽기·불일치 재시도와 주 이미지 RAM 송신기·기록 명령을 원본 ARM으로 검증했습니다. 프로그램 함수의 오류 2가 명령 0xA 응답에 저장되지 않는 지점, 후속 비교, 실제 갱신의 섹터 순서와 최대 16회 시도를 구분해 확인했습니다. 합성 메모리 검사 43건이며 물리 기록·전체 설치는 미검증입니다.

2026-11-08 UI 후속: RAW File Format의 PEF=0·DNG=1과 설정 0x97의 선택·적용·취소를 연결했습니다. 텍스트 준비 12건, 이벤트 12건과 래퍼 상태 2건을 재현했습니다. 기종 간 숫자 ID·바이너리 호환성이나 실제 LCD 표시는 입증하지 않았습니다.

[무손실 재포장·원본 업데이트 검사](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/rebuild.html) · [렌즈 능력·AF 구동 분기](https://yunhyok.github.io/pentax-k3ii-firmware-analysis/analysis/af-drive.html) · [연구 목표별 상태](analysis/hq-status.json)

2026-11-08 재포장 후속: 무수정 파일의 완전 일치와 같은 크기 메뉴 글자 수정 후보를 검증했습니다. 주·보조 이미지의 서로 다른 체크섬과 원본 복호화 전체를 대조하고, 명령 7 송신기·수신기를 함께 실행해 덧셈 결과를 확인했습니다. 실기 설치·부팅·촬영은 미검증입니다. `python verify_repack.py <원본 경로> --compare analysis/repack.json`으로 재현할 수 있습니다.

2026-11-08 AF 후속: 렌즈 명령 `0x8205` 응답의 bit 6 생산·저장·조회와 렌즈 명령/바디 드라이버 분기를 연결했습니다. 합성 구동 6건과 내부 모델 분기 3건을 원본 ARM으로 실행했습니다. 실물 렌즈 식별·구동은 미확인이며 모델별 패치를 적용하지 않았습니다. `python verify_af_drive.py decoded.bin --emulate --compare analysis/af-drive.json`으로 재현할 수 있습니다.

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
톤 함수 C 재컴파일에는 pyelftools와 Zig 0.17.1도 필요합니다. 설치·빌드 옵션은 [재현 안내](analysis/tone-rebuild.html#reproduce)에 정리했습니다.

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
python verify_repack.py <fwdc230b.bin 경로> --compare analysis/repack.json
python verify_af_drive.py .private/decoded/decoded.bin --emulate --compare analysis/af-drive.json
python verify_af_control.py .private/decoded/decoded.bin --emulate --compare analysis/af-control.json
python verify_af_input.py .private/decoded/decoded.bin --compare analysis/af-input.json
python verify_installation.py .private/decoded/decoded.bin --emulate --compare analysis/installation.json
python verify_ui_resources.py .private/decoded/decoded.bin --compare analysis/ui-resources.json
python verify_color_ui.py .private/decoded/decoded.bin --compare analysis/color-ui.json
python verify_ui_dispatch.py .private/decoded/decoded.bin --compare analysis/ui-dispatch.json
python verify_settings_storage.py .private/decoded/decoded.bin --compare analysis/settings-storage.json
python verify_preserved_record.py .private/decoded/decoded.bin --compare analysis/preserved-record.json
python verify_pixel_records.py .private/decoded/decoded.bin --compare analysis/pixel-records.json
python verify_pixel_policy.py .private/decoded/decoded.bin --compare analysis/pixel-policy.json
python verify_capture_prepare.py .private/decoded/decoded.bin --compare analysis/capture-prepare.json
python verify_tone_rebuild.py .private/decoded/decoded.bin --zig <Zig-0.17.1-실행파일> --compare analysis/tone-rebuild.json
python -m unittest discover -s tests -v
python verify_publication.py
```

분석 도구는 GPL-2.0으로 배포합니다. 난독화 알고리즘 출처와 공개 범위는 [HTML 보고서](index.html#sources)에 정리했습니다. 제조사 펌웨어에는 이 저장소의 라이선스가 적용되지 않습니다.
