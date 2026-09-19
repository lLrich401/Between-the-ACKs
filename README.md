# Between the ACKs — 출제자 기술 문서

> **The message was never in the payload.**
> 참가자는 정체불명의 stateful network appliance를 외부에서 실험적으로 역공학하여,
> 패킷들의 **관계(길이·지연 차이·순서·세그먼트 형태)** 에서 프로토콜을 복원하고 `LR{...}`를 완성한다.

- 플래그: `LR{b3tw33n_th3_ACKs_1s_wh3r3_th3_pr0t0c0l_l1v3s}`
- 포트: TCP **9001** (gate), TCP **9002** (finale), UDP **20001~20002** (트랜지언트, 2개)
- 배포: Dreamhack wargame (리포지토리 `between-the-acks`, 태그 `v0.3` 이상)
- 난이도 목표: 마스터 / 숙련 팀 4~8시간+
- 제공물: Dreamhack VM 접속 정보만 (소스·PCAP·문서 일절 없음)

---

## 1. 전체 아키텍처

```
                            ┌──────────────────────────────┐
 participant ── TCP 9001 ──▶│ Gate (Layer A+B 자동항)       │
                            │  probe → banner → token →     │
                            │  echo/segmentation → FIN      │
                            │  → half-close 오라클          │
                            └──────────────┬───────────────┘
                                           │ genuine 세션만
                                           ▼
                            ┌──────────────────────────────┐
 participant ── UDP 20k ───▶│ Transient UDP (15s TTL)      │◀─ Glob (Layer C)
                            │  20001~20002 상시 바인드,     │
                            │  sid → tk(8B) 1회             │
                            │  응답 포트 = 20001+(L3 mod 2) │
                            └──────────────┬───────────────┘
                                           │ sid+tk
                            ┌──────────────▼───────────────┐
 participant ── TCP 9002 ──▶│ Finale (ACK 오라클 최종단)    │
                            │  12 exchange → leak16 → blob  │
                            │  → fragment 발급(전역 순번)   │
                            └──────────────────────────────┘
```

- 전부 **Python 표준 라이브러리 + 일반 TCP/UDP 소켓**. raw socket, root capability, nftables **불필요** → Dreamhack VM 컨테이너에서 그대로 재현됨.
- 모든 관측값(응답 길이, 지연 페어 delta, echo, FIN 시점)은 **서버가 의도적으로 통제하는 값**이다. 커널/경로 우연값(NAT 재작성 필드, IP ID, 절대 RTT)에 의존하지 않는다.

## 2. Hidden State Machine (정확한 정의)

### Layer A — Transport Automaton (연결 형태)
| 검사 | 조건 | 결과 |
|---|---|---|
| probe 형태 | 첫 16바이트가 **≥3개의 read-event**로 도착 (solver는 4바이트×4회, gap 60ms) | `shaped=True/False` |
| 위반 시 | 단일 write(1 event) | **decoy 경로** (이후 모든 단계가 정상처럼 보이나 최종 실패) |

### Layer B — Session Automaton (연결당, `Sess`)
```
S0 ──(shaped probe 16B)──▶ BANNER ──(token 정답)──▶ ECHO ──(4×1B 분할+EOF)──▶ HC ──(UDP+제2연결)──▶ FINALE
 │                          │                        │
 └─ token 오답: fail++,     └─ token 오답: ERR,      └─ 분할/타이밍 위반: seg_ok=False
    새 challenge로 reset       challenge 재생성          (조용히 decoy 상태로 이동, ERR 없음)
    (fail>4 → poisoned)
```

### Layer C — Global Automaton (VM 전체, `Glob`)
| 상태 | 의미 |
|---|---|
| `sessions{sid_int→Sess}` | 10분 TTL 세션 테이블 |
| `run_counter` | 완료된 finale 수 = **fragment 발급 순번** (0..3) |
| `last_leak` | 직전 세션의 leak → **다음 세션의 K 계산에 체인** (transcript dependency) |
| `ip_sems` | **IP당 동시 gate 세션 6개** 제한 |
| UDP 응답 게이트 | `sess.udp_deadline`(15s) + `udp_done`(1회) + genuine 여부 |

## 3. 각 state의 transition 조건 (와이어 정확 규격)

모든 서버 응답은 **2바이트 big-endian 길이 prefix + payload**.

| 단계 | 트리거 | 서버 동작 | 참가자 관측값 |
|---|---|---|---|
| connect | — | 무응답 대기 | 침묵 |
| probe | 16B 수신(events≥3) | `jit(dA)` 대기 → blob0, `jit(dB)` 대기 → blobT(24B) | blob0 길이 `24+a`, **delay 페어 (80,200) 또는 (200,80)ms** |
| token | 1B | 정답: 60ms 후 blob1(24B) → echo 모드 / 오답: `ERR\n`, challenge 재생성 | blob1 magic `0xC2` vs `ERR\n` |
| segmentation | 4바이트를 1byte/event, gap 15ms~2s | 각 바이트 **즉시 echo** 후 EOF 대기 | 4회 1바이트 echo (ACK progression) |
| half-close | client `shutdown(WR)` | genuine: `jit(dA)` 후 L3길이 응답, `jit(dB)` 후 32B 응답 / decoy: (350,350) | **delta = t(응답1)−t(응답2)**: genuine \|δ\|∈[70,170], decoy \|δ\|<60; `c`: δ<0→c=0, δ>0→c=1; **L3 = 응답1 길이** |
| UDP | sid 4B 수신 (15s 내, 응답 포트 한정) | tk 8B 응답 1회, 이후/타 포트 침묵 | tk 획득 |
| finale(C2) | `sid+tk` 12B | 12 exchange: 각 exchange 응답1(길이 2..5)+응답2(8B) | real \|δ\|<95, decoy \|δ\|≥140; real 길이−2 = 2bit → leak16 |
| finale 종료 | 8번째 real exchange 후 | 50ms 후 blob(12B) 발급 | fragment |

타이밍 상수: `JIT=±25ms`, 배너 (80,200)ms, HC (80,200)ms / decoy 350ms, finale real 60ms / decoy (60,250)ms.

## 4. 참가자가 관측할 수 있는 signal (요약)

1. **응답 길이**: `a = len(blob0)−24 ∈ [0,15]`, `L3 = len(hc1)`, finale 길이 2..5
2. **지연 페어 delta** (절대값 아님!): 배너 δ → `b`, HC δ → `c` + decoy 판별, finale δ → real/decoy
3. **ACK progression**: echo 모드에서 바이트당 1 echo; coalesce 시 echo 횟수/묶음이 달라짐
4. **half-close semantics**: FIN 이후에도 읽어야 L3 응답 수령 (close() 즉시 호출 시 손실)
5. **세그먼트 형태**: 1바이트/event vs 통짜 → echo transcript 차이
6. **UDP 응답 포트**: `20001 + (L3 mod 2)` — 세션별로 달라지며, 관측으로 관계 확립 가능
7. **leak16**: finale real 응답 길이−2 를 2bit씩 순서대로 연결
8. **전역 순번**: leak 상위 4비트 = fragment index (0..3)

## 5. decoy signal

| decoy | 겉모습 | 분리 방법 |
|---|---|---|
| 단일 write probe | 이후 모든 단계 정상 진행 | 배너 δ≈0 (페어 지연 동일), HC δ≈0, UDP 침묵 |
| 세그먼트 위반(gap>2s 등) | 동일 | HC δ≈0 |
| finale decoy 응답 | 길이 2..5로 실제와 유사 | 페어 지연 δ≈±180ms vs real \|δ\|<40 |
| 무의미한 지연 노이즈 | ±25ms jitter | 반복 측정 시 중앙값으로 분리 (jitter ≪ 클래스 간격) |
| payload 전체 | 바이트 내용은 무의미한 랜덤 | 차이는 오직 관측값의 **관계**에만 존재 |

## 6. session challenge 생성

- 연결마다 `sid(4B 랜덤)`, `a∈[0,15]`, `b∈{0,1}`, `c∈{0,1}`, `L3∈[1,700]` 새로 생성.
- `a`는 blob0 **길이**, `b`는 배너 **지연 페어 순서**로만 노출 → 평문 전송 없음.
- 참가자는 differential probing으로 `token = (3a + 5b + 0x41) & 0xFF`를 역피팅해야 함 (오답→reset이 피드백 오라클).

## 7. replay 방지

- challenge `(a,b,c)` 연결마다 재생성 → 이전 성공 token 재사용 불가.
- `sid` 연결 유니크, UDP tk **1회 발급**, finale `used` 플래그 → `sid+tk` 재사용 시 `ERR` (테스트 `test_replay_rejected` 확인).
- 실패 시 challenge 재생성 → 동일 probe 재전송 무의미.

## 8. TCP 서비스 구현

`challenge/server.py` — thread-per-connection, `TCP_NODELAY`, 길이-prefix 프레이밍, `recv` 이벤트 타임스탬프 측정, `shutdown(SHUT_WR)` 기반 half-close. 9001=gate, 9002=finale.

## 9. UDP 서비스 구현 (Dreamhack 대응)

Dreamhack은 Specfile에 선언된 포트만 포워딩하므로 **동적 바인드가 불가능**하다. 따라서:

- 서버 기동 시 **20001, 20002 두 포트를 상시 바인드** (ICMP unreachable 오라클 부재 → 포트 스캔으로 상태 추론 불가)
- genuine 세션이 half-close에 도달하면 `sess.tk = os.urandom(8)`, `sess.udp_deadline = now+15s` 설정
- `udp_responder` 스레드: 수신 sid가 유효 세션의 것이고 **도착 포트 == `20001 + (L3 mod 2)`** 이며 TTL 내 1회만 `tk` 응답
- decoy/만료/재요청/잘못된 포트 → **침묵**

즉 "트랜지언트"의 성질(짧은 응답 창, 세션 종속성)은 소켓 수명이 아니라 **세션 상태 게이팅**으로 구현된다.

## 10. global state manager

`Glob` (threading.Lock 보호): 세션 테이블·run_counter·last_leak·IP당 동시성 세마포어. TCP/UDP가 동일 객체를 공유 → cross-protocol state.

## 11. 트랜지언트 포트

`응답 포트 = 20001 + (L3 mod 2)` (L3는 half-close 응답 길이로 관측). 참가자는 여러 세션에서 L3와 응답 포트의 관계를 관측해 확립하거나, 세션당 후보 2개를 시도한다. 전체 포트 스캔은 의미가 없다 — 세션이 genuine가 아니면 두 포트 모두 침묵하기 때문.

## 12. 동시 접속 처리

thread-per-connection + 전역 세마포(64) + **IP당 동시 gate 세션 6개** (BoundedSemaphore, 120초 대기 후 드롭). 초과 접속은 큐잉되며, 대기 중 probe가 병합되어 decoy화 — 남발이 자연히 저품질 세션으로 귀결(§14).

## 13. timeout 정책

probe 유휴 30s, 단계별 recv 2~30s, UDP 창 15s, 세션 레코드 10min GC, C2 입력 15s, finale 교환 10s. 조용히 종료(ERR 남발 없음).

## 14. anti-bruteforce

1. token 오답 → challenge 리셋(누적 학습만 가능, 연결당 5회 실패 시 poisoned=ERR 루프)
2. UDP tk 1회성 + 15초 창 + 세션 종속(genuine 전제)
3. finale `sid+tk` 1회
4. IP당 동시 세션 6 제한(초과 시 대기→품질 저하)
5. 전역 fragment는 **순서대로** 발급 → 병렬로 같은 fragment를 못 받음

## 15. Docker / Dreamhack VM 구성

```
between-the-acks/
├── Specfile            # [wargame] + [vm] (ports: 9001/tcp, 9002/tcp, 20001/udp, 20002/udp)
├── Description.md      # 문제 설명(시문) — 메커니즘 힌트 없음
├── Dockerfile          # python:3.12-slim, COPY deploy/server.py + /flag, 2개 UDP EXPOSE
├── deploy/             # 빌드 컨텍스트: server.py + flag(실제 플래그)
├── public/             # 공개 파일 없음 (README 안내만)
└── private/            # 출제자용: 본 문서, solver, 테스트
```

Dreamhack 할당 포트 ↔ 내부 포트 매핑은 표시 순서대로 대응 → solver의 `--udp-ports`에 할당된 2개 UDP 포트를 순서대로 전달.

## 16. 필요한 Linux capability

**없음.** 일반 소켓만 사용(CAP_NET_RAW 불필요). 비-root 실행 가능.

## 17. 방화벽 / nftables

불필요. 트랜지언트 응답 게이트는 애플리케이션 상태로 구현. 방화벽이 있다면 9001/9002/tcp, 20001-20002/udp만 허용.

## 18. 서버 코드 구조

```
server.py
├─ 상수/플래그 로딩(env BTA_FLAG → /flag → 기본값)·청킹 (split_flag, keystream)
├─ Sess (연결별 hidden state) / Glob (전역 상태)
├─ read_probe / echo_phase / read_exact   ← Layer A·B 측정
├─ udp_responder ×2                       ← 상시 바인드 + 세션 게이팅 (§9)
├─ finale / reserve_finale               ← leak16·K 체인·fragment 발급
├─ handle (9001) / handle_c2 (9002)
└─ listener / gc_loop / main
```

## 19. intended solution

1. `--probe` 모드로 배너 길이 분포(24..39)와 **지연 페어 delta**의 쌍봉 분포 발견
2. probe 형태 실험(단일 write vs 분할)로 Layer A 트랩 발견
3. 다수 세션의 (a,b) 관측 + 성공/실패 피드백으로 `token = (3a+5b+0x41)&0xFF` 선형 피팅
4. token 성공 = echo 모드 진입 발견 → 1바이트 분할 전송이 ACK progression을 만든다는 것 관측
5. half-close(FIN) 후 응답 2개의 **delta**가 세션마다 ±120ms로 요동치는 것 관측 → `c` 추출, δ≈0 세션은 decoy
6. half-close 응답1 길이 L3 ↔ 응답하는 UDP 포트 관계 관측 → `20001 + L3 mod 2` 확립
7. UDP로 sid→tk 교환, C2에 `sid+tk`
8. finale에서 delta 기반 real/decoy 분리 후 길이−2로 leak16 복원
9. 4세션 반복, 세션 n의 blob을 `K_n = (leak_n ^ leak_{n-1}) & 0xFFF`, `ks_j = K_n ^ (j*37)` XOR로 복호화(세션 0의 `LR{` 크리브로 가설 검증)
10. 순서대로 결합 → `LR{...}`

## 20. 단계별 solve reasoning

| 관찰 | 비교 | 가설 | 검증 |
|---|---|---|---|
| 침묵 후 응답 | 한 번에 보내기 vs 나눠 보내기 | 형태 검사 존재 | 배너 δ 분포 |
| 길이 24..39 변동 | 세션 간 비교 | 길이=파라미터 a | a 고정 후 token 성공률 상승 |
| 지연 두 클러스터 | 페어 내 순서 | δ 부호가 bit | token 피팅 정확도 |
| echo 존재/부재 | token 값별 | token 진입 신호 | ERR과 비교 |
| 1바이트 echo 4회 vs 묶음 | 전송 단위별 | 세그먼트 트랩 | δ≈0 세션과 비교 |
| HC δ 부호 | 세션 간 | 숨겨진 bit c | K 가설 검증 |
| L3 값 변동 | 응답하는 UDP 포트 | 사상 관계 | 세션 간 회귀 |
| blob 비ASCII | leak·크리브 | XOR 체인 | `LR{` 확인 |

## 21. 최종 solver

`solve/solver.py` — connection 생성, 지연 측정·페어 분류, token 계산, 세그먼트 분할 전송, half-close, UDP 포트 선택, finale delta 분류, leak 조립, 4세션 transcript 저장, `decode()` 복원. `--probe N`은 intended RE 도구(분포 분석). Dreamhack에서는 `--udp-ports <할당된 2개>` 사용. Scapy 불필요 — 단, tcpdump/wireshark로 δ·길이를 보는 것이 RE 루트.

## 22. 플래그 복원 과정

- 플래그 48바이트를 12바이트씩 4분할(공백 패딩).
- 세션 n: `K_n = ((3a+5b+7c+(L3&0x3F)) & 0xFFF) ^ (leak_{n-1} & 0xFFF)` (서버 내부), `leak_n = (idx<<12) | (K_n ^ prev)`.
- 참가자는 `K_n = (leak_n ^ leak_{n-1}) & 0xFFF`로 복원하고 `plain[j] = blob[j] ^ (K_n ^ j*37 & 0xFF)`.
- 세션 0은 `prev=0`에서 시작, 세션 1..3은 **이전 세션 transcript의 leak가 반드시 필요** → 단일 연결 반복으로는 불가능.

## 23. 예상 unintended solution

- 토큰 256 전수(연결당 5회 제한+리셋 → 연결당 최대 5 후보, 비용 급증)
- 2개 UDP 포트 전송 시도 (genuine 세션 없으면 양쪽 침묵 — 상태 게이트가 진짜 방어선)
- delta 타이밍 무시하고 절대 RTT 사용 (VM 부하 시 오분류 → 스스로 상대비교로 전환하게 됨)
- blob/leak을 payload로 직접 읽으려는 시도 (blob은 XOR로 비ASCII, leak는 길이+delta 조합)

## 24. unintended 방지책

- replay·전수 시도는 상태 무효화/쿨다운으로 자가 파괴
- nonce·tk는 서버 발급 1회용
- 관측값 재사용 불가(연결별 재생성)
- IP당 동시성 제한으로 자동화 남발 저속화
- decoy 경로가 "성공처럼" 끝까지 진행시켜 무작위 스캐닝의 가치를 떨어뜨림

## 25. 네트워크 환경 불안정 요소

| 요소 | 영향 |
|---|---|
| RTT 변동 | 절대 지연 분류 오류 가능 |
| 중간 장비의 세그먼트 병합 | read-event 카운트 왜곡 |
| 서버 부하/GIL | sleep 오버런 |
| Dreamhack 포트 매핑 | 외부 포트↔내부 포트 순서 가정 필요 |

## 26. 각 불안정 요소의 수정 방법

1. **절대 타이밍 의존 제거**: 모든 비트를 **페어 delta/순서**로 인코딩 (공통모드 상쇄). 추가 완화: `D_*` 상수와 `DELTA_MIN` 동시 증가.
2. 병합 내성: probe는 events≥3 (1회 병합 허용), 세그먼트 트랩은 **gap 하한 15ms**(클라이언트 sleep으로 결정적) + 상한 2s로 기아 영향 제거.
3. 부하 억제: IP당 동시 6 제한 — 초과 시 큐잉·decoy화는 의도된 동작.
4. Dreamhack 포트 매핑: Specfile 순서대로 할당된다는 전제 + 최악의 경우 2개 포트를 모두 시도해도 동작(정답 포트만 응답).
5. NAT/경로 재작성 필드(IP ID, TTL, window 정밀값 등)는 **일절 사용하지 않음**.

## 27. 로컬 테스트

```
python tests\e2e_local.py        # 서버 기동 → probe 분석 → 4세션 → 플래그 복원 검증
python tests\negative_test.py    # decoy 경로 / token 전수 처벌 / finale replay 거부
python solve\solver.py 127.0.0.1 --probe 20   # intended RE 도구(분포)
python solve\solver.py <host>                 # full solve
```

## 28. 부하 테스트

```
python solve\loadtest.py --workers 6 --rounds 3    # 설계 동시성: 전부 성공 (검증됨, median ~3.2s)
python solve\loadtest.py --workers 16 --rounds 1   # 과부하: 일부 decoy화(의도) + 서버 생존 확인
```

과부하에서 일부 세션이 decoy로 귀결되는 것은 IP당 동시성 제한에 의한 **의도된 저하**이며, 서버는 응답 가능 상태 유지(`server responsive after load`).

## 29. 난이도 조절 포인트

- `token` 계수(3,5,0x41) 변경 → 피팅 난이도
- `DELTA_MIN`, 지연 클래스 간격, `JIT` → 타이밍 채널 난이도
- `keystream(k,n)`의 `j*37`·`K` 수식 → 복호화 추론 난이도
- `NUDP`(2) → UDP 포트 발견/사상 난이도 (늘리면 계산성 상승, 줄이면 단순화)
- decoy 수(finale 4/12), probe 요구 event 수, `PER_IP_LIMIT`
- `NFRAG`/플래그 길이 → 필요 세션 수

## 30. 출제자용 검증 체크리스트

- [x] `python tests\e2e_local.py` → `FLAG: LR{...}` `[PASS]`
- [x] `python tests\negative_test.py` → decoy·poison·replay 전부 `[PASS]`
- [x] `python solve\loadtest.py --workers 6` → 무결 + 서버 생존
- [x] 단일 write probe → decoy 경로(δ≈0) + UDP 침묵 확인
- [x] token 5회 오답 → poisoned ERR 루프 확인
- [x] `sid+tk` 재사용 → ERR 확인
- [x] raw socket / CAP_* / nftables 미사용 확인
- [x] 절대 RTT·NAT 재작성 필드·커널 미정의 동작 미의존 (delta 방식)
- [x] Dreamhack 배포: v0.1 검증 이슈(public 비어있음) → v0.2 수정, v0.3 = UDP 2포트 체계
- [x] Dreamhack 테스트: Manage 서버 생성 → `python solver.py <host> --udp-ports <2개>` → 플래그 확인

---

### 배포 요약

- 로컬: `cd challenge && python server.py` (또는 docker compose)
- Dreamhack: 리포지토리 `between-the-acks`, 변경 시 커밋 → 새 태그 → Deploy 탭에서 검증/배포
- 참가자: `nc <host> <port>` 로 접속하면 아무것도 보이지 않는다 — 그것이 시작점이다.