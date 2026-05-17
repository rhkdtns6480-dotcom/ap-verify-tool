# Packet Sender/Receiver 기능 정의서 v1.1

**프로젝트:** AP Auto Verification Tool
**모듈명:** Packet S/D (Send / Receive)
**작성일:** 2026-05-17
**상태:** 확정 (개발 준비)

---

## 1. 동작 모드

### 1.1 모드 정의

| 모드 | 설명 |
|---|---|
| Sender → Receiver | 단방향. Sender가 보내고 Receiver가 받음 |
| Receiver → Sender | 단방향. 반대 방향 |
| Bidirectional | 양방향 동시. Master-Slave 각각 송수신 동시 수행 |
| Send Only | 송신만. 수신 확인 없음 |
| Receive Only | 수신 대기만. 외부 장비 대응 |

### 1.2 인터페이스 역할 매핑

모든 모드에서 Sender / Receiver 인터페이스를 Master 또는 Slave 중 사용자가 직접 선택

### 1.3 NAT Mode AP 세션 선개통 처리 (핵심)

```
구성: [Master] --- [NAT AP] --- [Slave]

문제:
  포트포워딩 설정 없이는 Master → Slave 직접 전송 불가

해결: NAT 세션 선개통
  Step 1. Slave가 먼저 Master 방향으로 패킷 전송
          → NAT AP에 세션 테이블 자동 생성
          → 세션: Slave내부IP:Port ↔ AP_WAN_IP:NAT_Port

  Step 2. Scapy로 Master 인터페이스에서 첫 수신 패킷 캡처
          → Src IP = AP WAN IP, Src Port = NAT Port 파악

  Step 3. Master는 AP_WAN_IP:NAT_Port로 응답 전송
          → AP 세션 테이블 참조 → Slave에게 포워딩

  세션 유지: UDP 약 30~300초, TCP 연결 동안 유지
  NAT 모드 감지 시 항상 Slave를 Sender로 먼저 시작
```

---

## 2. 프로토콜별 구현

### 2.1 UDP (1차 구현)

- 비연결형, Scapy sendp() 직접 전송
- RTT: 페이로드 타임스탬프 + Echo 응답 방식
- 손실: Sequence Number 직접 관리

### 2.2 TCP (2차 구현)

UDP vs TCP 구현 차이:

| 항목 | UDP | TCP |
|---|---|---|
| 연결 수립 | 없음 | SYN → SYN-ACK → ACK |
| 신뢰성 | 없음 (직접 구현) | OS 스택 자동 처리 |
| 순서 보장 | 없음 | 있음 |
| Scapy 전송 | sendp() 단순 전송 | 복잡 (아래 참조) |
| 손실 감지 | Seq 직접 관리 | TCP Seq/ACK 활용 |

TCP 구현 옵션:

옵션 A - Python socket (1차, 권장)
  - socket.create_connection()으로 연결
  - OS TCP 스택 활용 (재전송, 순서보장 자동)
  - 한계: 인터페이스 직접 지정 불가
  - 복잡도: 낮음

옵션 B - Scapy Raw TCP (2차)
  - SYN 직접 생성 → SYN-ACK 수신 → ACK → 데이터
  - 특정 인터페이스 직접 지정 가능
  - Windows 문제: OS가 SYN-ACK 보고 RST 전송
    (OS가 자신이 SYN 안 보냈다고 판단)
    해결: Windows 방화벽 규칙 추가 또는 RAW 소켓 필터
  - 복잡도: 높음

결론: 1차 socket 방식, 2차 Scapy Raw TCP

### 2.3 RTT 측정 방식 (프로토콜별)

UDP:
  Sender가 페이로드에 타임스탬프 삽입
  Receiver가 즉시 Echo 응답
  Sender: (Echo 수신 시각) - (페이로드 타임스탬프) = RTT

TCP:
  소켓 방식: 데이터 송신 ~ ACK 수신 시간
  Scapy 방식: SYN 전송 ~ SYN-ACK 수신 시간

### 2.4 NAT 환경 패킷 식별 방법

문제: Receiver에서 Src IP = AP WAN IP (NAT 변환됨)
      → IP 기반 식별 불가

해결: 페이로드 Magic Number + Seq 기반 식별

페이로드 헤더 구조 (16바이트):
  [Magic 4B: 0x41505644] [Seq 4B: 0~N] [Timestamp 8B: float64]
  APVD = AP Verify Data

Echo 응답 목적지:
  NAT 모드: 수신 패킷의 Src IP:Src Port (= AP WAN IP:NAT Port)
  직결 모드: 수신 패킷의 Src IP:Src Port (= 실제 Sender IP:Port)

---

## 3. 전송 설정

| 항목 | 옵션 | 범위 |
|---|---|---|
| 수량 | 지정 패킷 수 / 시간 지정 / 지속 전송 | 1~무제한 / 1초~999시간 |
| 속도 | PPS / Mbps / 최대속도 | 1~100,000 PPS |
| 패킷 크기 | 고정 / 랜덤 / 프리셋 | 64~9000 byte |
| 페이로드 | APVD 패턴 / All Zero / All FF / 사용자 정의 | |
| TTL | 사용자 설정 | 기본 64 |
| Src Port | 고정 / 랜덤 | |
| Dst Port | 고정 | 기본 19999 |

---

## 4. 실시간 통계 UI

```
┌────────────┐  ┌────────────┐  ┌────────────┐
│   송신      │  │   수신      │  │   손실      │
│   12,345   │  │   12,320   │  │    25      │
│   패킷     │  │   패킷     │  │   0.20%    │
└────────────┘  └────────────┘  └────────────┘

┌────────────┐  ┌────────────┐  ┌────────────┐
│  평균 RTT  │  │   처리량    │  │    지터     │
│   2.3ms   │  │  9.8 Mbps  │  │   0.8ms    │
└────────────┘  └────────────┘  └────────────┘

경과: 00:00:05   상태: ● 실행 중
```

임계값 초과 시:
  손실률 > 1.0% → 손실 카운터 빨강 + WARN 로그
  RTT > 100ms   → RTT 표시 주황
  지터 > 10ms   → 지터 표시 주황

---

## 5. 결과 출력

Syslog:
  [Packet S/D] 시작: UDP Slave→Master PPS=1000 크기=1024B 시간=60초
  [Packet S/D] 진행: 송=5000 수=4990 손=10(0.20%) RTT=2.3ms
  [Packet S/D] WARN: 손실률 1.2% 임계값(1.0%) 초과
  [Packet S/D] 완료: 송=60000 수=59880 손실=0.20% RTT평균=2.3ms PASS

Excel 시트 (Packet_SD):
  - 설정 요약 (프로토콜, IP, 포트, PPS, 시간, 크기)
  - 총 송신/수신/손실 수, 손실률
  - RTT 평균/최소/최대, 지터
  - 처리량 (Mbps)
  - 임계값 초과 이벤트 목록
  - PASS / FAIL 판정

PDF:
  - 설정 요약 테이블
  - 통계 결과 테이블
  - PASS / FAIL 판정 및 사유

---

## 6. 개발 단계 (확정)

| 단계 | 내용 |
|---|---|
| 1단계 | UDP Send Only / Receive Only, PPS 제어, 기본 통계 UI |
| 2단계 | Sender+Receiver 연동, Echo RTT, 손실률, 임계값 알람 |
| 3단계 | NAT 세션 선개통 (Slave 선송신 + NAT Port 캡처) |
| 4단계 | Bidirectional 양방향 동시, 방향별 독립 통계 |
| 5단계 | TCP 구현 (Python socket 방식) |
| 6단계 | Syslog / Excel / PDF 결과서 연동 |
| 7단계 | TCP Scapy Raw 방식 (옵션, 추후) |

---

## 7. 미결 사항

| # | 항목 | 상태 |
|---|---|---|
| 1 | TCP 1차: socket 방식 | 확정 |
| 2 | NAT 세션: Slave 선송신 | 확정 |
| 3 | RTT: 페이로드 TS + Echo | 확정 |
| 4 | 패킷 식별: Magic+Seq | 확정 |
| 5 | UI: 텍스트 통계 카운터 박스 | 확정 |
| 6 | NAT Port 파악: Scapy 캡처 Src Port 추출 | 검토 중 |
| 7 | TCP Scapy Windows RST 문제 | 추후 검토 |
| 8 | Bidirectional sniff+send 동시 성능 | 테스트 필요 |
