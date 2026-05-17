# AP Auto Verification Tool v0.0.1

AP(Access Point) 자동 검증 도구 — Python / Tkinter / Scapy 기반

---

## 주요 기능

### 토폴로지
- psutil 기반 인터페이스 자동 감지
- Master / Slave 역할 지정
- AP 자동 감지 (Bridge / NAT Mode)
  - Master + Slave 동시: ARP 스캔 + MAC 교차 분석
  - Master만: GW ARP → 공인IP: Internet망 / 사설IP: AP(NAT)
  - Slave만: GW ARP → 공인IP: AP(Bridge) / 사설IP: AP(NAT)
  - NAT CPE 뒤 Bridge AP 감지 지원
- 수동 AP 추가 (WAN/LAN MAC 입력, ARP 확인)
- 노드 드래그 이동 (좌클릭)
- 노드 간 연결 드래그 (우클릭)
- 30초 주기 자동 연결 모니터 (ARP + Ping)
- 우측 상태 요약 패널 (Master/Slave/DUT AP 정보)
- IP 설정 (고정/DHCP, Gateway/DNS 포함, netsh 적용)

### Packet S/D
- UDP 송수신 테스트 (TCP 추후 지원)
- 동작 모드: S→R / R→S / 양방향 / 송신만 / 수신만
- 토폴로지 Master/Slave 자동 연동
- PPS / Mbps / 최대속도 설정
- 패킷수 / 시간 / 지속 전송
- NAT 세션 선개통 (Slave 선송신 → NAT Port 자동 파악)
- 실시간 통계: 송신/수신/손실/RTT/처리량/지터
- 임계값 알람

### 기능 검증 시나리오
- DHCP / NAT / IGMP / Packet S/D 플러그인 (구현 진행 중)

### 규격 검증 시나리오
- Step 기반 시나리오 편집 및 실행

### Syslog
- 레벨 필터 (DEBUG/INFO/WARN/ERROR)
- 검색, 파일 저장

### 결과서 설정
- Excel + PDF 결과서 생성

---

## 요구사항

```
Python      3.12+
Scapy       2.7.0+
psutil      5.x+
openpyxl    3.x+
reportlab   4.x+
Npcap       1.80+ (WinPcap 호환 모드 필수)
```

```powershell
pip install scapy psutil openpyxl reportlab
```

---

## 실행

```powershell
# 관리자 권한 필요 (netsh IP 설정, Scapy RAW 소켓)
python main_app.py
```

관리자 권한이 없으면 UAC 팝업이 뜨고 자동 재실행됩니다.

---

## 빌드 (exe)

```powershell
# Npcap 설치파일을 폴더에 넣으면 함께 번들됨
python build.py
# 결과물: dist/AP_Verify_Tool.exe
```

---

## GitHub 업데이트

```powershell
.\push.ps1
```

자동으로:
1. 날짜별 버전 스냅샷 생성
2. 릴리즈 노트 작성
3. 커밋 메시지 입력
4. git push

---

## 파일 구조

```
ap_verify_tool/
├── main_app.py          메인 GUI (8탭)
├── packet_sd.py         Packet S/D 엔진
├── scenario_engine.py   시나리오 실행 엔진
├── report_writer.py     Excel + PDF 결과서
├── logger.py            Syslog
├── npcap_check.py       Npcap 설치 확인
├── build.py             PyInstaller 빌드
├── push.ps1             GitHub 자동 업로드
├── app.manifest         Windows 관리자 권한
├── requirements.txt
├── docs/
│   └── packet_sd_spec.md   Packet S/D 기능 정의서
├── plugins/
│   ├── base_plugin.py
│   └── dummy_plugins.py
└── scenarios/           JSON 시나리오 파일
```

---

## 개발 현황

| 기능 | 상태 |
|---|---|
| 토폴로지 / AP 감지 | ✅ 완료 |
| IP 설정 (netsh) | ✅ 완료 |
| 30초 자동 모니터 | ✅ 완료 |
| Packet S/D (UDP) | ✅ 완료 |
| Packet S/D (TCP) | 🔄 구현 예정 |
| DHCP 플러그인 | 🔄 구현 예정 |
| NAT 플러그인 | 🔄 구현 예정 |
| IGMP 플러그인 | 🔄 구현 예정 |
| 결과서 (Excel/PDF) | 🔄 연동 예정 |
