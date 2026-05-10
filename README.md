# AP Auto Verification Tool

> Windows 기반 AP(Access Point) 자동 검증 도구  
> Python + Tkinter GUI · Scapy 패킷 엔진 · Plugin Architecture

---

## 개요

AP 검증에 필요한 DHCP, NAT, IGMP 등의 기능을 플러그인 형태로 구성하고,  
Master/Slave 인터페이스 간 실제 패킷 송수신을 통해 자동 검증하는 툴입니다.

```
[Master NIC] ─── [DUT AP] ─── [Slave NIC]
  DHCP Server       NAT/Bridge     DHCP Client
  이더넷 4           자동 감지       Wi-Fi
```

---

## 주요 기능

| 탭 | 기능 |
|---|---|
| **토폴로지** | 인터페이스 Master/Slave 지정, AP 자동 감지(NAT/Bridge), 연결상태 확인(ARP+ICMP) |
| **기능 검증** | 플러그인별 표준 검증 항목 (DHCP/NAT/IGMP/Packet S/D) |
| **시나리오 검증** | 커스텀 Step 시나리오 편집·실행, 반복/Aging 테스트 |
| **Syslog** | 레벨별 로그 필터, 파일 저장 (RotatingFileHandler) |
| **결과서** | Excel (.xlsx) + PDF 자동 생성 |
| **환경설정** | 경로, 타임아웃, 보고서 헤더 설정 |

### 핵심 기능 상세

- **가상 MAC 관리** — Scapy로 가상 MAC 최대 50개 생성, 각각 독립 DHCP 요청
- **AP 자동 감지** — ARP 스캔으로 Bridge/NAT Mode 자동 판별, 토폴로지에 DUT AP 표시
- **실제 패킷 모드** — Scapy + Npcap으로 지정 인터페이스에서 실제 ARP/ICMP 송신
- **시뮬레이션 모드** — Scapy/Npcap 미설치 시 자동 fallback

---

## 환경 요구사항

### 필수

| 항목 | 버전 | 비고 |
|---|---|---|
| **Windows** | 10 / 11 (64-bit) | Linux/Mac 미지원 |
| **Python** | 3.10 이상 (권장 3.14) | |
| **Npcap** | 1.80 이상 | 패킷 캡처 드라이버 |
| **관리자 권한** | 필수 | RAW 소켓 사용 |

### Python 패키지

| 패키지 | 버전 | 용도 |
|---|---|---|
| `scapy` | 2.7.0+ | 패킷 송수신 (ARP/ICMP/DHCP) |
| `psutil` | 5.9.0+ | 네트워크 인터페이스 열거 |
| `openpyxl` | 3.1.0+ | Excel 결과서 생성 |
| `reportlab` | 4.0.0+ | PDF 결과서 생성 |
| `tkinter` | 내장 | GUI (Python 기본 포함) |

---

## 설치 방법

### 1. Npcap 설치 (필수, 최초 1회)

```
https://npcap.com/#download
```
> ⚠️ 설치 옵션에서 **"WinPcap API-compatible Mode"** 반드시 체크

### 2. Python 패키지 설치

```powershell
# 반드시 실행에 사용하는 python.exe 경로로 설치
python -m pip install scapy psutil openpyxl reportlab
```

### 3. 실행

```powershell
# 반드시 관리자 권한으로 실행
python main_app.py
```

---

## exe 빌드 방법

```powershell
# 빌드 전: npcap-1.80.exe를 프로젝트 폴더에 복사해두면 자동 번들됨
python build.py

# 디버그 모드 (콘솔 창 유지)
python build.py --debug

# 폴더 방식 빌드 (빠름, 디버깅용)
python build.py --onedir
```

빌드 완료 후 `dist/AP_Verify_Tool.exe` 생성  
타겟 PC에 Npcap이 없으면 앱 시작 시 자동 설치 안내 다이얼로그 표시

---

## 프로젝트 구조

```
ap_verify_tool/
├── main_app.py              ← 메인 GUI (6탭)
├── virtual_mac_manager.py   ← 가상 MAC / DHCP 클라이언트
├── npcap_check.py           ← Npcap 설치 확인 및 자동 설치
├── scenario_engine.py       ← 시나리오 실행 엔진 (반복/Aging)
├── report_writer.py         ← Excel + PDF 결과서
├── logger.py                ← Syslog (RotatingFileHandler)
├── build.py                 ← PyInstaller 빌드 스크립트
├── app.manifest             ← Windows 관리자 권한 설정
├── requirements.txt
├── plugins/
│   ├── base_plugin.py       ← 플러그인 베이스 클래스
│   └── dummy_plugins.py     ← DHCP/NAT/IGMP/PacketSD (개발 중)
├── scenarios/               ← 시나리오 JSON 파일
│   ├── dhcp_basic.json
│   ├── dhcp_aging.json
│   ├── nat_port.json
│   └── igmp_join.json
└── release_notes/           ← 버전별 릴리즈 노트
    └── RELEASE_20260510.md
```

---

## 사용 방법

### 기본 검증 흐름

1. **토폴로지 탭** → 인터페이스 선택 → Master/Slave 지정
2. **📡 AP 감지** 버튼 → DUT AP 자동 감지 및 모드 표시 (NAT/Bridge)
3. **🔗 연결상태 확인** → ARP + ICMP Ping으로 연결 검증
4. **기능 검증 탭** → 플러그인 선택 → 표준 검증 실행
5. **결과서 탭** → Excel/PDF 결과보고서 다운로드

### 가상 MAC DHCP 테스트

1. 토폴로지 탭 → 인터페이스 카드 → **가상 MAC** 버튼
2. **일괄 생성** → MAC 수(최대 50개) + OUI 프리픽스 입력
3. **▶ 전체 DHCP 요청** → 병렬로 각 MAC에 IP 할당 요청
4. 할당된 IP 목록 실시간 확인

---

## GitHub 업데이트 방법

프로젝트 루트에서 `push.ps1` 실행:

```powershell
.\push.ps1
```

자동으로 실행:
- 날짜별 스냅샷 파일 생성 (`main_app_YYYYMMDD.py`)
- 릴리즈 노트 작성 프롬프트 (`release_notes/RELEASE_YYYYMMDD.md`)
- git add / commit / push

---

## 릴리즈 히스토리

| 버전 | 날짜 | 주요 변경 |
|---|---|---|
| v0.0.1 | 2026-05-10 | 최초 릴리즈 — 전체 골격 구현 |

> 상세 내역: [`release_notes/`](./release_notes/) 폴더 참조

---

## 개발 로드맵

- [ ] DHCP 플러그인 실제 구현 (Scapy 기반)
- [ ] NAT 플러그인 실제 구현
- [ ] IGMP 플러그인 실제 구현
- [ ] 기능 검증 탭 각 플러그인별 검증 UI
- [ ] PDF 한글 폰트 완전 지원
- [ ] 코드서명 인증서 적용

---

## 라이선스

Private — 개인 프로젝트

---

*개발: lightSUN · 문의: rhkdtns6480@gmail.com*
