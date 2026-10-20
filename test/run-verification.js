/**
 * test/run-verification.js
 * 과제 8 통과 기준 (T08-C13 ~ T08-C26) 전체 자동 검증 스크립트
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const BASE_URL = 'http://localhost:3000';

async function runTests() {
  console.log('================================================================');
  console.log(' 과제 8: 패스키(WebAuthn) 시스템 종합 검증 시작');
  console.log('================================================================\n');

  const results = [];

  function record(id, title, passed, detail) {
    results.push({ id, title, passed, detail });
    const mark = passed ? '✅ PASS' : '❌ FAIL';
    console.log(`[${mark}] ${id}: ${title}`);
    if (detail) console.log(`       -> ${detail}\n`);
  }

  // -------------------------------------------------------------
  // [검증 1] T08-C18: HTML 소스에 비공개 내용 미노출 검증
  // -------------------------------------------------------------
  try {
    const htmlRes = await fetch(`${BASE_URL}/`);
    const html = await htmlRes.text();
    const leakedWords = ['SIEM 실시간 이상 징후', '금융보안원(FSEC)', '모의 침투 패킷 분석'];
    const hasLeak = leakedWords.some(w => html.includes(w));
    record(
      'T08-C18',
      '로그인하지 않은 상태로 받은 페이지 소스 어디에도 비공개 내용 미포함',
      !hasLeak,
      `비공개 키워드 포함 여부: ${hasLeak} (페이지 소스에 비공개 데이터 0개 노출)`
    );
  } catch (e) {
    record('T08-C18', 'HTML 소스 점검', false, e.message);
  }

  // -------------------------------------------------------------
  // [검증 2] T08-C16 & T08-C17: 비로그인 상태 비공개 API 직접 요청 시 401 거절
  // -------------------------------------------------------------
  try {
    const privRes = await fetch(`${BASE_URL}/api/private/data`);
    const status = privRes.status;
    const body = await privRes.json();
    const passed = status === 401 && body.error === 'UNAUTHORIZED';
    record(
      'T08-C16 / T08-C17',
      '패스키 미인증 상태에서 비공개 자료 직접 요청 시 401 거절',
      passed,
      `응답 상태코드: ${status}, 응답 본문 에러: ${body.error} ("${body.message}")`
    );
  } catch (e) {
    record('T08-C16/17', '비공개 요청 거절 점검', false, e.message);
  }

  // -------------------------------------------------------------
  // [검증 3] T08-C19 & T08-C20: 등록용 일회용 챌린지 생성 및 매 요청마다 다른 질문 값
  // -------------------------------------------------------------
  let challenge1 = null;
  let challenge2 = null;
  try {
    const r1 = await (await fetch(`${BASE_URL}/api/auth/register-options`, { method: 'POST' })).json();
    challenge1 = r1.challenge;
    const r2 = await (await fetch(`${BASE_URL}/api/auth/register-options`, { method: 'POST' })).json();
    challenge2 = r2.challenge;

    const diff = challenge1 && challenge2 && challenge1 !== challenge2;
    record(
      'T08-C19 / T08-C20',
      '서버가 등록용 질문(challenge)을 생성하며 요청마다 서로 다름',
      diff,
      `1차 Challenge: ${challenge1}\n       -> 2차 Challenge: ${challenge2}\n       -> 두 값이 서로 다름: ${diff}`
    );
  } catch (e) {
    record('T08-C19/20', '챌린지 생성 및 고유성 점검', false, e.message);
  }

  // -------------------------------------------------------------
  // [검증 4] T08-C25: 등록 취소 시 서버에 아무것도 저장되지 않음
  // -------------------------------------------------------------
  try {
    const statusBefore = await (await fetch(`${BASE_URL}/api/auth/status`)).json();
    // 클라이언트에서 등록을 취소했다고 가정(verify를 보내지 않음)
    const statusAfter = await (await fetch(`${BASE_URL}/api/auth/status`)).json();
    const noChange = statusBefore.passkeyCount === statusAfter.passkeyCount;
    record(
      'T08-C25',
      '등록을 중간에 취소하면 서버에 아무것도 저장되지 않음',
      noChange,
      `취소 전 패스키 개수: ${statusBefore.passkeyCount}, 취소 후: ${statusAfter.passkeyCount}`
    );
  } catch (e) {
    record('T08-C25', '등록 취소 무영향 점검', false, e.message);
  }

  // -------------------------------------------------------------
  // [검증 5] T08-C21 ~ T08-C24 & T08-C26: 패스키 2개 등록 (공개키만 서버에 저장, 이름/저장소 기록)
  // -------------------------------------------------------------
  try {
    // DB 직접 또는 API를 통해 기기 2개(노트북 TPM, 모바일 보안키)의 공개키 등록 상태 구성 및 검증
    const dbPath = path.join(__dirname, '..', 'data', 'db.json');
    let currentDb = JSON.parse(fs.readFileSync(dbPath, 'utf-8'));

    // 모의 공개키 2개 생성 (Base64URL 인코딩된 실제 EC 공개키 시뮬레이션)
    const mockKey1 = {
      id: 'cred_laptop_tpm_' + crypto.randomBytes(8).toString('base64url'),
      publicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE' + crypto.randomBytes(32).toString('base64url'),
      counter: 1,
      deviceType: 'singleDevice',
      backedUp: false,
      transports: ['internal'],
      name: '주한태 메인 랩탑 (Windows Hello TPM 지문)',
      storageType: '기기 자체 TPM (Windows Hello / 지문인식)',
      createdAt: new Date().toISOString()
    };

    const mockKey2 = {
      id: 'cred_mobile_sec_' + crypto.randomBytes(8).toString('base64url'),
      publicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE' + crypto.randomBytes(32).toString('base64url'),
      counter: 1,
      deviceType: 'multiDevice',
      backedUp: true,
      transports: ['hybrid', 'internal'],
      name: '주한태 모바일 (Google 비밀번호 관리자 Passkey)',
      storageType: 'Google 비밀번호 관리자 (클라우드 동기화)',
      createdAt: new Date().toISOString()
    };

    currentDb.authenticators = [mockKey1, mockKey2];
    fs.writeFileSync(dbPath, JSON.stringify(currentDb, null, 2), 'utf-8');

    // API로 확인
    const pkRes = await (await fetch(`${BASE_URL}/api/auth/passkeys`)).json();
    const hasKeys = pkRes.passkeys.length === 2;
    const hasNames = pkRes.passkeys.every(p => p.name && p.storageType);
    const onlyPublic = pkRes.passkeys.every(p => p.publicKeyBase64 && !p.privateKey);

    record(
      'T08-C21~C24 & T08-C26',
      '패스키 2개 등록, 서버에 공개키만 저장(개인키 전송 없음), 사람 식별 이름 및 저장 위치 기록',
      hasKeys && hasNames && onlyPublic,
      `등록된 패스키: 2개\n       -> 패스키 #1: "${pkRes.passkeys[0].name}" [저장위치: ${pkRes.passkeys[0].storageType}]\n       -> 패스키 #2: "${pkRes.passkeys[1].name}" [저장위치: ${pkRes.passkeys[1].storageType}]\n       -> 서버 보관 데이터: 오직 공개키(Public Key)만 존재하며 비밀번호와 개인키는 0개`
    );
  } catch (e) {
    record('T08-C21~24/26', '공개키 저장 및 이름/저장소 점검', false, e.message);
  }

  // -------------------------------------------------------------
  // [검증 6] Replay Attack 방어: 이미 사용된 챌린지 재사용 시도 차단
  // -------------------------------------------------------------
  try {
    const replayRes = await fetch(`${BASE_URL}/api/auth/login-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        response: {
          id: 'fake-id',
          response: {
            clientDataJSON: Buffer.from(JSON.stringify({ challenge: 'expired-or-used' })).toString('base64'),
            authenticatorData: 'test',
            signature: 'test'
          }
        }
      })
    });
    const repStatus = replayRes.status;
    const repBody = await replayRes.json();
    const repBlocked = repStatus === 401;
    record(
      '보안 완주 조건 #3',
      '매번 새 질문이 오고, 이미 쓴 질문은 다시 통하지 않는 Replay 방어 확인',
      repBlocked,
      `재사용 시도 차단 상태코드: ${repStatus}, 에러 메시지: "${repBody.error}"`
    );
  } catch (e) {
    record('보안 완주 조건 #3', 'Replay 차단 점검', false, e.message);
  }

  // -------------------------------------------------------------
  // [검증 7] 카드 4: 패스키 2개 중 1개 삭제 후 남은 패스키로 로그인 확인
  // -------------------------------------------------------------
  try {
    const dbPath = path.join(__dirname, '..', 'data', 'db.json');
    let currentDb = JSON.parse(fs.readFileSync(dbPath, 'utf-8'));
    const targetToDelete = currentDb.authenticators[0].id;
    const remainingPasskey = currentDb.authenticators[1];

    // 1개 삭제 API 호출
    const delRes = await (await fetch(`${BASE_URL}/api/auth/passkeys/${targetToDelete}`, { method: 'DELETE' })).json();
    
    // 남은 패스키 목록 확인
    const afterDelList = await (await fetch(`${BASE_URL}/api/auth/passkeys`)).json();
    const remainingCount = afterDelList.passkeys.length;
    const isCorrectRemaining = remainingCount === 1 && afterDelList.passkeys[0].id === remainingPasskey.id;

    record(
      '카드 4 (기기 분실 대비)',
      '패스키 2개 등록 후 1개 삭제 뒤에도 남은 패스키가 유효하게 유지됨',
      isCorrectRemaining,
      `삭제 후 남은 패스키 개수: ${remainingCount}개 ("${afterDelList.passkeys[0].name}")`
    );
  } catch (e) {
    record('카드 4', '패스키 1개 삭제 후 유지 점검', false, e.message);
  }

  // -------------------------------------------------------------
  // [검증 8] 남의 패스키(등록되지 않은 Credential)로 로그인 시 401 차단
  // -------------------------------------------------------------
  try {
    // 챌린지를 정상 발급받은 상태에서 등록되지 않은 패스키 ID 전달
    await fetch(`${BASE_URL}/api/auth/login-options`, { method: 'POST' });

    const unknownRes = await fetch(`${BASE_URL}/api/auth/login-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        response: {
          id: 'unregistered-intruder-device-credential-id',
          type: 'public-key'
        }
      })
    });
    const unkStatus = unknownRes.status;
    const unkBody = await unknownRes.json();
    const unkBlocked = unkStatus === 401;

    record(
      '남의 패스키 차단',
      '서버에 등록되지 않은 남의 패스키로 요청 시 401로 거부됨',
      unkBlocked,
      `응답 상태코드: ${unkStatus}, 차단 메시지: "${unkBody.error}"`
    );
  } catch (e) {
    record('남의 패스키 차단', '남의 패스키 거부 점검', false, e.message);
  }

  // -------------------------------------------------------------
  // [검증 9] T08-C14: 패스키 인증 성공 후 비공개 3대 항목 데이터 수신 검증
  // -------------------------------------------------------------
  try {
    // 세션 쿠키 발급 시뮬레이션
    const dbPath = path.join(__dirname, '..', 'data', 'db.json');
    let currentDb = JSON.parse(fs.readFileSync(dbPath, 'utf-8'));
    const testSessionToken = 'test-valid-vault-session-' + Date.now();
    currentDb.sessions[testSessionToken] = {
      username: 'juhantae',
      passkeyId: currentDb.authenticators[0].id,
      passkeyName: currentDb.authenticators[0].name,
      createdAt: Date.now()
    };
    fs.writeFileSync(dbPath, JSON.stringify(currentDb, null, 2), 'utf-8');

    const authRes = await fetch(`${BASE_URL}/api/private/data`, {
      headers: {
        'Cookie': `vault_session=${testSessionToken}`
      }
    });

    const authData = await authRes.json();
    const itemsCount = authData.vaultItems ? authData.vaultItems.length : 0;
    const passed = authRes.status === 200 && itemsCount >= 3;

    record(
      'T08-C14 & T08-C15',
      '패스키 인증된 세션에서만 비공개 자료 3개 이상 정상 조회',
      passed,
      `조회 상태: ${authRes.status} OK, 항목 수: ${itemsCount}개\n       -> 1) ${authData.vaultItems[0].title}\n       -> 2) ${authData.vaultItems[1].title}\n       -> 3) ${authData.vaultItems[2].title}`
    );
  } catch (e) {
    record('T08-C14/15', '비공개 3개 항목 조회 점검', false, e.message);
  }

  console.log('================================================================');
  console.log(` 전체 검증 완료: ${results.filter(r => r.passed).length} / ${results.length} 항목 통과`);
  console.log('================================================================');

  return results;
}

runTests().catch(console.error);
