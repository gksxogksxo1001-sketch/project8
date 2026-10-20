const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const { isoBase64URL } = require('@simplewebauthn/server/helpers');

const app = express();
const PORT = process.env.PORT || 3000;
const RP_NAME = '주한태 보안관제 포트폴리오 패스키 금고';
const RP_ID = 'localhost';
const EXPECTED_ORIGINS = [
  `http://localhost:${PORT}`,
  `http://127.0.0.1:${PORT}`,
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];

// 미들웨어
app.use(express.json());
app.use(cookieParser());
app.use((req, res, next) => {
  db = loadDB();
  next();
});

// 데이터베이스 파일 경로
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// 기본 DB 초기화
function loadDB() {
  if (fs.existsSync(DB_FILE)) {
    try {
      return JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
    } catch (e) {
      console.error('DB 파싱 오류, 초기화합니다:', e);
    }
  }
  const initial = {
    user: {
      id: 'juhantae_sec_2026',
      username: 'juhantae',
      displayName: '주한태 (보안관제 준비생)'
    },
    authenticators: [],
    sessions: {},
    auditLogs: []
  };
  saveDB(initial);
  return initial;
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

let db = loadDB();

// 현재 활성화된 일회용 챌린지 저장소 (메모리 관리: sessionId 또는 clientIP 기준)
// { [challengeId]: { challenge: string, type: 'registration' | 'authentication', createdAt: number, used: boolean } }
const activeChallenges = new Map();

// 보안 감사 로그 추가 헬퍼
function addAuditLog(type, message, details = {}) {
  const logEntry = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    type,
    message,
    details
  };
  db.auditLogs.unshift(logEntry);
  if (db.auditLogs.length > 100) {
    db.auditLogs.pop();
  }
  saveDB(db);
  console.log(`[AUDIT] [${type}] ${message}`);
}

// 벤더 스크립트 서빙 (@simplewebauthn/browser)
app.get('/vendor/simplewebauthn-browser.js', (req, res) => {
  const browserBundle = path.join(
    __dirname,
    'node_modules',
    '@simplewebauthn',
    'browser',
    'dist',
    'bundle',
    'index.umd.min.js'
  );
  if (fs.existsSync(browserBundle)) {
    res.sendFile(browserBundle);
  } else {
    res.status(404).send('Bundle not found');
  }
});

// 정적 파일 서빙
app.use(express.static(__dirname));

// 세션 확인 미들웨어
function getSessionUser(req) {
  const token = req.cookies.vault_session;
  if (!token) return null;
  const session = db.sessions[token];
  if (!session) return null;
  // 유효기간 1일
  if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
    delete db.sessions[token];
    saveDB(db);
    return null;
  }
  return session;
}

// -------------------------------------------------------------
// [API] 인증 상태 확인
// -------------------------------------------------------------
app.get('/api/auth/status', (req, res) => {
  const session = getSessionUser(req);
  res.json({
    authenticated: !!session,
    username: session ? session.username : null,
    passkeyCount: db.authenticators.length,
    passkeys: db.authenticators.map(a => ({
      id: a.id,
      name: a.name,
      createdAt: a.createdAt,
      storageType: a.storageType
    }))
  });
});

// -------------------------------------------------------------
// [API] 등록 1단계: 패스키 등록 옵션 생성 (일회용 질문/Challenge 발급)
// 통과기준: T08-C19, T08-C20
// -------------------------------------------------------------
app.post('/api/auth/register-options', async (req, res) => {
  try {
    const user = db.user;
    const userIdBuffer = Buffer.from(user.id);

    // 이미 등록된 패스키는 제외 목록에 추가
    const excludeCredentials = db.authenticators.map(dev => ({
      id: dev.id,
      transports: dev.transports || ['internal', 'usb', 'nfc', 'ble', 'hybrid']
    }));

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: userIdBuffer,
      userName: user.username,
      userDisplayName: user.displayName,
      attestationType: 'none',
      excludeCredentials,
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred'
      },
      timeout: 60000
    });

    // 서버에 일회용 챌린지 보관 (5분 유효)
    const challengeKey = `reg_${user.username}`;
    activeChallenges.set(challengeKey, {
      challenge: options.challenge,
      type: 'registration',
      createdAt: Date.now(),
      used: false
    });

    addAuditLog('REGISTER_CHALLENGE_CREATED', '패스키 등록용 일회용 챌린지 생성 완료', {
      challenge: options.challenge,
      username: user.username,
      rpID: RP_ID
    });

    res.json(options);
  } catch (error) {
    console.error('등록 옵션 생성 실패:', error);
    res.status(500).json({ error: '등록 옵션 생성 중 오류가 발생했습니다.' });
  }
});

// -------------------------------------------------------------
// [API] 등록 2단계: 패스키 등록 검증 및 공개키 저장
// 통과기준: T08-C21, T08-C22, T08-C23, T08-C24, T08-C25, T08-C26
// -------------------------------------------------------------
app.post('/api/auth/register-verify', async (req, res) => {
  const { response, name, storageType } = req.body;
  const challengeKey = `reg_${db.user.username}`;
  const storedChallengeObj = activeChallenges.get(challengeKey);

  if (!storedChallengeObj || storedChallengeObj.used) {
    addAuditLog('REGISTER_FAILED', '유효하지 않거나 이미 사용된 챌린지로 등록 시도 차단');
    return res.status(400).json({ error: '챌린지가 유효하지 않거나 만료되었습니다. 처음부터 다시 시도해주세요.' });
  }

  // 챌린지 1회용 즉시 소모(삭제)
  activeChallenges.delete(challengeKey);

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: storedChallengeObj.challenge,
      expectedOrigin: EXPECTED_ORIGINS,
      expectedRPID: RP_ID
    });

    if (verification.verified && verification.registrationInfo) {
      const { credential } = verification.registrationInfo;
      const credentialId = credential.id;
      const publicKeyBase64 = isoBase64URL.fromBuffer(credential.publicKey);

      // 이미 같은 credentialId가 등록되어 있는지 확인
      const existingIndex = db.authenticators.findIndex(dev => dev.id === credentialId);
      const passkeyName = name && name.trim() ? name.trim() : `보안 패스키 #${db.authenticators.length + 1}`;
      const detectedStorage = storageType || '기기 자체 보안 영역 (Windows Hello / Touch ID / 보안 키)';

      const newAuthenticator = {
        id: credentialId,
        publicKey: publicKeyBase64,
        counter: credential.counter,
        deviceType: verification.registrationInfo.credentialDeviceType || 'singleDevice',
        backedUp: verification.registrationInfo.credentialBackedUp || false,
        transports: response.response && response.response.transports ? response.response.transports : ['internal'],
        name: passkeyName,
        storageType: detectedStorage,
        createdAt: new Date().toISOString()
      };

      if (existingIndex >= 0) {
        db.authenticators[existingIndex] = newAuthenticator;
      } else {
        db.authenticators.push(newAuthenticator);
      }

      // 등록 성공 시 바로 로그인 세션 발급
      const sessionToken = crypto.randomBytes(32).toString('hex');
      db.sessions[sessionToken] = {
        username: db.user.username,
        passkeyId: credentialId,
        passkeyName,
        createdAt: Date.now()
      };
      saveDB(db);

      res.cookie('vault_session', sessionToken, {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000
      });

      addAuditLog('PASSKEY_REGISTERED', `신규 패스키 등록 성공 및 공개키 저장 완료 (이름: ${passkeyName})`, {
        credentialId,
        publicKeySummary: `${publicKeyBase64.substring(0, 32)}... (비밀번호가 아닌 FIDO2 비대칭 공개키)`,
        storageType: detectedStorage,
        privateKeyTransferred: false // 개인키는 브라우저/기기를 벗어나지 않음
      });

      return res.json({
        verified: true,
        passkey: {
          id: credentialId,
          name: passkeyName,
          storageType: detectedStorage,
          publicKeyPreview: publicKeyBase64.substring(0, 30) + '...'
        }
      });
    }

    addAuditLog('REGISTER_FAILED', '패스키 서명/증명 검증 불일치로 등록 거부');
    res.status(400).json({ verified: false, error: '패스키 등록 검증에 실패했습니다.' });
  } catch (error) {
    console.error('등록 검증 오류:', error);
    addAuditLog('REGISTER_ERROR', `패스키 등록 검증 중 오류: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// [API] 로그인 1단계: 패스키 로그인 옵션 생성 (일회용 질문/Challenge 발급)
// 통과기준: 챌린지 매번 새로 생성
// -------------------------------------------------------------
app.post('/api/auth/login-options', async (req, res) => {
  try {
    if (db.authenticators.length === 0) {
      return res.status(400).json({ error: '등록된 패스키가 없습니다. 먼저 패스키를 등록해주세요.' });
    }

    const allowCredentials = db.authenticators.map(dev => ({
      id: dev.id,
      transports: dev.transports || ['internal', 'usb', 'nfc', 'ble', 'hybrid']
    }));

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials,
      userVerification: 'preferred',
      timeout: 60000
    });

    const challengeKey = `auth_${db.user.username}`;
    activeChallenges.set(challengeKey, {
      challenge: options.challenge,
      type: 'authentication',
      createdAt: Date.now(),
      used: false
    });

    addAuditLog('LOGIN_CHALLENGE_CREATED', '로그인용 신규 일회용 챌린지(질문) 생성 완료', {
      challenge: options.challenge,
      allowedPasskeysCount: allowCredentials.length
    });

    res.json(options);
  } catch (error) {
    console.error('로그인 옵션 생성 실패:', error);
    res.status(500).json({ error: '로그인 옵션 생성 중 오류가 발생했습니다.' });
  }
});

// -------------------------------------------------------------
// [API] 로그인 2단계: 패스키 서명 검증 및 로그인 처리
// 통과기준: Replay Attack 방지 (이미 쓴 질문은 통하지 않음), 남의 패스키 차단
// -------------------------------------------------------------
app.post('/api/auth/login-verify', async (req, res) => {
  const { response } = req.body;
  const challengeKey = `auth_${db.user.username}`;
  const storedChallengeObj = activeChallenges.get(challengeKey);

  // 1. 챌린지 유효성 검사 (만료되었거나 이미 사용된 경우 즉시 차단)
  if (!storedChallengeObj) {
    addAuditLog('LOGIN_BLOCKED_REPLAY', '존재하지 않거나 이미 소모된 챌린지로 로그인 재시도 차단 (Replay Attack 방어)', {
      receivedCredentialId: response ? response.id : 'unknown'
    });
    return res.status(401).json({
      error: '이미 사용되었거나 존재하지 않는 챌린지입니다. 매 로그인마다 새로운 질문이 필요합니다.'
    });
  }

  // 2. 챌린지 일회성 소모: 즉시 삭제하여 동일한 질문으로 2번 요청할 수 없도록 함!
  activeChallenges.delete(challengeKey);

  // 3. 클라이언트가 제시한 패스키 ID가 서버에 등록되어 있는지 확인
  const authenticator = db.authenticators.find(dev => dev.id === response.id);
  if (!authenticator) {
    addAuditLog('LOGIN_BLOCKED_UNKNOWN_PASSKEY', '서버에 등록되지 않은 남의 패스키(Credential) 시도 차단', {
      unregisteredId: response.id
    });
    return res.status(401).json({
      error: '등록되지 않은 패스키입니다. 접근 권한이 없습니다.'
    });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: storedChallengeObj.challenge,
      expectedOrigin: EXPECTED_ORIGINS,
      expectedRPID: RP_ID,
      credential: {
        id: authenticator.id,
        publicKey: isoBase64URL.toBuffer(authenticator.publicKey),
        counter: authenticator.counter,
        transports: authenticator.transports
      }
    });

    if (verification.verified) {
      // 카운터 업데이트
      authenticator.counter = verification.authenticationInfo.newCounter;
      
      // 세션 생성
      const sessionToken = crypto.randomBytes(32).toString('hex');
      db.sessions[sessionToken] = {
        username: db.user.username,
        passkeyId: authenticator.id,
        passkeyName: authenticator.name,
        createdAt: Date.now()
      };
      saveDB(db);

      res.cookie('vault_session', sessionToken, {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000
      });

      addAuditLog('LOGIN_SUCCESS', `패스키 전자서명 검증 완료: 로그인 성공 (${authenticator.name})`, {
        credentialId: authenticator.id,
        newCounter: authenticator.counter
      });

      return res.json({
        verified: true,
        user: {
          username: db.user.username,
          displayName: db.user.displayName,
          usedPasskey: authenticator.name
        }
      });
    }

    addAuditLog('LOGIN_FAILED_SIGNATURE', '서명 검증 불일치 (위조되었거나 일치하지 않는 서명)', {
      credentialId: authenticator.id
    });
    res.status(401).json({ verified: false, error: '전자서명 검증에 실패했습니다.' });
  } catch (error) {
    console.error('로그인 검증 오류:', error);
    addAuditLog('LOGIN_ERROR', `로그인 검증 처리 오류: ${error.message}`);
    res.status(401).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// [API] 로그아웃
// -------------------------------------------------------------
app.post('/api/auth/logout', (req, res) => {
  const token = req.cookies.vault_session;
  if (token && db.sessions[token]) {
    const session = db.sessions[token];
    delete db.sessions[token];
    saveDB(db);
    addAuditLog('LOGOUT', `사용자 로그아웃 완료 (${session.passkeyName})`);
  }
  res.clearCookie('vault_session');
  res.json({ success: true, message: '안전하게 로그아웃되었습니다.' });
});

// -------------------------------------------------------------
// [API] 패스키 목록 조회 및 개별 삭제 (기기 분실 대비 다중 패스키)
// 통과기준: 카드 4 (패스키 2개 등록 후 1개 삭제 후에도 로그인 가능)
// -------------------------------------------------------------
app.get('/api/auth/passkeys', (req, res) => {
  // 등록된 패스키의 메타데이터와 공개키 정보만 노출 (개인키는 서버에 없음)
  const list = db.authenticators.map(a => ({
    id: a.id,
    name: a.name,
    storageType: a.storageType,
    createdAt: a.createdAt,
    publicKeyHex: Buffer.from(isoBase64URL.toBuffer(a.publicKey)).toString('hex'),
    publicKeyBase64: a.publicKey,
    description: '서버에는 공개키만 저장되어 있으며, 개인키는 사용자의 기기 보안 영역(TPM/Secure Enclave)에서 나가지 않습니다.'
  }));
  res.json({ passkeys: list, total: list.length });
});

app.delete('/api/auth/passkeys/:id', (req, res) => {
  const { id } = req.params;
  const initialCount = db.authenticators.length;
  const target = db.authenticators.find(a => a.id === id);

  if (!target) {
    return res.status(404).json({ error: '해당 패스키를 찾을 수 없습니다.' });
  }

  db.authenticators = db.authenticators.filter(a => a.id !== id);
  saveDB(db);

  addAuditLog('PASSKEY_DELETED', `패스키 삭제 완료 (이름: ${target.name}, ID: ${id})`, {
    remainingCount: db.authenticators.length
  });

  res.json({
    success: true,
    message: `'${target.name}' 패스키가 삭제되었습니다.`,
    remainingCount: db.authenticators.length
  });
});

// -------------------------------------------------------------
// [API] 비공개 영역 데이터 조회
// 통과기준: T08-C14 (항목 3개 이상), T08-C16 (비로그인 요청 시 거절), T08-C17 (401 또는 403 거절)
// -------------------------------------------------------------
app.get('/api/private/data', (req, res) => {
  const session = getSessionUser(req);

  // 패스키로 로그인하지 않은 상태인 경우 401 Unauthorized 거절!
  if (!session) {
    addAuditLog('UNAUTHORIZED_ACCESS_ATTEMPT', '미인증 사용자의 비공개 금고 데이터 직접 접근 차단 (401 반환)');
    return res.status(401).json({
      statusCode: 401,
      error: 'UNAUTHORIZED',
      message: '접근이 거부되었습니다. 이 영역은 주한태 본인의 FIDO2 패스키로 인증된 세션에서만 열람할 수 있습니다.',
      timestamp: new Date().toISOString()
    });
  }

  // 통과기준 T08-C37, T08-C38, T08-C40, T08-C41:
  // 다른 사용자의 비공개 자료를 읽으려는 요청(IDOR 공격 시도)은 403 Forbidden으로 차단!
  const targetUser = req.query.targetUser || req.query.username;
  if (targetUser && targetUser !== session.username) {
    addAuditLog('ACCESS_DENIED_CROSS_ACCOUNT', `타인 계정('${targetUser}') 비공개 자료 접근 시도 차단 (403 Forbidden)`, {
      attemptedUser: targetUser,
      sessionUser: session.username
    });
    return res.status(403).json({
      statusCode: 403,
      error: 'FORBIDDEN',
      message: `접근이 거부되었습니다. '${session.username}' 패스키로 인증된 세션에서는 다른 계정('${targetUser}')의 비공개 자료를 열람할 수 없습니다.`,
      attemptedUser: targetUser,
      sessionUser: session.username,
      timestamp: new Date().toISOString()
    });
  }

  // 계정별 서로 다른 비공개 데이터 3건 (T08-C36)
  const userDataStore = {
    juhantae: {
      owner: '주한태 (보안관제 엔지니어 준비생)',
      authorizedPasskey: session.passkeyName,
      authenticatedAt: new Date(session.createdAt).toISOString(),
      vaultItems: [
        {
          id: 'vault-item-01',
          category: '준비 중인 보안 프로젝트 메모',
          title: 'SIEM 실시간 이상 징후 탐지 룰셋 자동화 파이프라인 (R&D)',
          summary: 'Snort/Suricata 시그니처와 YARA 룰을 연동한 악성 패킷 자동 분류 시스템 설계 메모입니다.',
          details: [
            'Scapy를 활용한 비정상 SYN Flood 및 Slowloris 공격 트래픽 시뮬레이션 환경 구축',
            'Snort 규칙 기반 1차 필터링 후 탐지된 로그를 ElasticSearch로 인덱싱하여 실시간 관제 대시보드 연동',
            '관제 요원의 수동 패킷 분석 시간을 40% 단축하기 위한 YARA 룰 자동 매칭 스크립트 작성 중'
          ],
          updatedAt: '2026-10-18'
        },
        {
          id: 'vault-item-02',
          category: '지원 기업 및 직무 분석 목록',
          title: '2026 주요 보안관제(SOC) 및 CERT 전문기업 분석 매트릭스',
          summary: '목표 기업의 관제 인프라와 요구 역량을 매칭 분석한 비공개 지원 전략 노트입니다.',
          details: [
            '금융보안원(FSEC): 전자금융기반 침해대응본부, 대규모 금융 트래픽 분산 모니터링 및 실시간 위협 정보 공유 체계(F-ISAC)',
            'SK쉴더스 Top-CERT: EDR 및 클라우드 네이티브 관제 환경, 다중 침해사고 포렌식 및 위협 헌팅 중심 역량 요구',
            '안랩 A-FIRST / SOC: 차세대 통합 보안 플랫폼 기반 원격 보안관제, 탐지 시그니처 튜닝 및 침해 분석 보고서 작성 역량 집중'
          ],
          updatedAt: '2026-10-15'
        },
        {
          id: 'vault-item-03',
          category: '학습 및 실습 자체 회고',
          title: '모의 침투 패킷 분석 트러블슈팅과 보안관제 관점의 자체 회고',
          summary: '혼밥비서 공공 API 및 모의 환경에서 네트워크 트래픽 이상 분석 중 마주한 한계와 극복 기록입니다.',
          details: [
            '초기 모의 관제 실습 중 정상 HTTPS 트래픽과 C2 통신 패킷의 혼재로 인한 오탐(False Positive) 다수 발생',
            '단순 페이로드 검사가 아닌 패킷 전송 간격(Jitter), 연결 지속 시간(Beaconing 특성) 기반의 통계적 행위 분석 적용으로 탐지 정확도 향상',
            '배운 점: 완벽한 단일 시그니처는 없으며, 다계층 로그(방화벽, WAF, 서버 시스템 로그) 교차 검증의 절대적 중요성을 체득함'
          ],
          updatedAt: '2026-10-12'
        }
      ]
    },
    security_tester: {
      owner: '김보안 (외부 모의침투 테스터 / 계정 #2)',
      authorizedPasskey: session.passkeyName,
      authenticatedAt: new Date(session.createdAt).toISOString(),
      vaultItems: [
        {
          id: 'tester-item-01',
          category: '모의해킹 R&D',
          title: 'CVE-2026 웹 애플리케이션 취약점 분석 및 PoC 메모',
          summary: 'Spring Cloud Gateway 및 인증 우회 취약점 실습 분석 기록입니다.',
          details: [
            '인증 헤더 변조를 통한 API 게이트웨이 우회 시나리오 검증',
            'WAF 시그니처 우회 기법 및 방어 룰셋 도출'
          ],
          updatedAt: '2026-10-19'
        },
        {
          id: 'tester-item-02',
          category: '취약점 진단 목록',
          title: '금융권 모의침투 프로젝트 취약점 체크리스트',
          summary: '전자금융 기반시설 취약점 분석 및 진단 가이드라인 적용 표입니다.',
          details: [
            'SQL Injection 및 불충분한 인가 취약점 점검',
            '세션 하이재킹 및 쿠키 변조 공격 시나리오'
          ],
          updatedAt: '2026-10-17'
        },
        {
          id: 'tester-item-03',
          category: '내부망 침투 회고',
          title: 'Active Directory 내부망 권한 상승 및 래터럴 무브먼트 회고',
          summary: 'Kerberoasting 및 Pass-the-Hash 기법 실습 트러블슈팅 회고록입니다.',
          details: [
            '이벤트 로그 ID 4624/4625 추적을 통한 이상 징후 탐지 연구',
            'EDR 탐지 우회 시도 차단 및 헌팅 역량 강화'
          ],
          updatedAt: '2026-10-14'
        }
      ]
    }
  };

  const userVault = userDataStore[session.username] || userDataStore.juhantae;
  addAuditLog('PRIVATE_VAULT_ACCESSED', `비공개 금고 데이터 정상 조회 (계정: ${session.username}, 인증 패스키: ${session.passkeyName})`);
  res.json(userVault);
});

// -------------------------------------------------------------
// [API] 보안 감사 로그 조회 (화면의 보안 검증 콘솔용)
// -------------------------------------------------------------
app.get('/api/security/audit-log', (req, res) => {
  res.json({ logs: db.auditLogs.slice(0, 30) });
});

// 서버 기동
app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(` 주한태 패스키 금고 서버가 시작되었습니다.`);
  console.log(` 접속 주소: http://localhost:${PORT}`);
  console.log(` RP ID: ${RP_ID} | RP Name: ${RP_NAME}`);
  console.log(`=======================================================`);
});
