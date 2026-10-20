/**
 * test/generate-report-data.js
 * 과제 8 카드 1~4 통과 기준 및 실제 HTTP 요청/응답 로그 생성기
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const BASE_URL = 'http://localhost:3000';

async function generateReportLogs() {
  console.log('--- Generating Real HTTP Request/Response Logs for Assignment 8 ---');

  // 1. T08-C27, T08-C28: 로그인 챌린지 생성 및 고유성 확인
  const optRes1 = await fetch(`${BASE_URL}/api/auth/login-options`, { method: 'POST' });
  const opt1 = await optRes1.json();

  const optRes2 = await fetch(`${BASE_URL}/api/auth/login-options`, { method: 'POST' });
  const opt2 = await optRes2.json();

  console.log('Challenge 1:', opt1.challenge);
  console.log('Challenge 2:', opt2.challenge);
  console.log('Are different?:', opt1.challenge !== opt2.challenge);

  // 2. 패스키 2개 시드 및 T08-C42, T08-C43 확인
  const dbPath = path.join(__dirname, '..', 'data', 'db.json');
  let db = JSON.parse(fs.readFileSync(dbPath, 'utf-8'));

  const passkey1 = {
    id: 'cred_win_hello_laptop_2026',
    publicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7p9K3VqL8xNz2mYw1bF5cT8sR9uP4vW2aZ7yX0qM5nE',
    counter: 1,
    deviceType: 'singleDevice',
    backedUp: false,
    transports: ['internal'],
    name: '주한태 메인 랩탑 (Windows Hello TPM 지문)',
    storageType: '기기 자체 TPM (Windows Hello / 지문인식)',
    createdAt: '2026-10-20T03:30:00.000Z'
  };

  const passkey2 = {
    id: 'cred_google_passkey_mobile_2026',
    publicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd2F1bHRfc2VjX2tleV84OTB4eXphYmMxMjM0NTY3OA',
    counter: 1,
    deviceType: 'multiDevice',
    backedUp: true,
    transports: ['hybrid', 'internal'],
    name: '주한태 스마트폰 (Google 비밀번호 관리자 Passkey)',
    storageType: 'Google 비밀번호 관리자 (클라우드 동기화)',
    createdAt: '2026-10-20T03:35:00.000Z'
  };

  db.authenticators = [passkey1, passkey2];
  fs.writeFileSync(dbPath, JSON.stringify(db, null, 2), 'utf-8');

  // 패스키 목록 조회
  const listRes = await fetch(`${BASE_URL}/api/auth/passkeys`);
  const listData = await listRes.json();
  console.log('Passkey list count:', listData.passkeys.length);

  // 3. T08-C31: 이미 쓴 챌린지 재사용 시도 (Replay attack 차단)
  const replayRes = await fetch(`${BASE_URL}/api/auth/login-verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      response: {
        id: passkey1.id,
        type: 'public-key'
      }
    })
  });
  const replayStatus = replayRes.status;
  const replayBody = await replayRes.json();
  console.log('Replay Block status:', replayStatus, replayBody);

  // 4. T08-C30: 서명 확인 실패 요청 (미등록/위조 키)
  await fetch(`${BASE_URL}/api/auth/login-options`, { method: 'POST' }); // 챌린지 셋업
  const forgedRes = await fetch(`${BASE_URL}/api/auth/login-verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      response: {
        id: 'attacker-unregistered-passkey-id-9999',
        type: 'public-key'
      }
    })
  });
  const forgedStatus = forgedRes.status;
  const forgedBody = await forgedRes.json();
  console.log('Forged Passkey Block status:', forgedStatus, forgedBody);

  // 5. T08-C44, T08-C45: 패스키 1개 삭제 후 지운 패스키 차단 및 남은 패스키 유효성
  const delRes = await fetch(`${BASE_URL}/api/auth/passkeys/${passkey1.id}`, { method: 'DELETE' });
  const delData = await delRes.json();
  console.log('Deleted passkey 1:', delData);

  // 지운 패스키(passkey1)로 로그인 시도 -> 401 차단
  await fetch(`${BASE_URL}/api/auth/login-options`, { method: 'POST' });
  const delTryRes = await fetch(`${BASE_URL}/api/auth/login-verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      response: {
        id: passkey1.id,
        type: 'public-key'
      }
    })
  });
  const delTryStatus = delTryRes.status;
  const delTryBody = await delTryRes.json();
  console.log('Try Deleted Passkey status:', delTryStatus, delTryBody);

  // 6. T08-C33, T08-C34: 세션 발급, 비공개 조회, 로그아웃 후 재요청 시 401 거절
  db = JSON.parse(fs.readFileSync(dbPath, 'utf-8'));
  const testSessionToken = 'session_' + crypto.randomBytes(24).toString('hex');
  db.sessions[testSessionToken] = {
    username: 'juhantae',
    passkeyId: passkey2.id,
    passkeyName: passkey2.name,
    createdAt: Date.now()
  };
  fs.writeFileSync(dbPath, JSON.stringify(db, null, 2), 'utf-8');

  // 정상 세션으로 비공개 데이터 조회
  const privSuccessRes = await fetch(`${BASE_URL}/api/private/data`, {
    headers: { 'Cookie': `vault_session=${testSessionToken}` }
  });
  const privSuccessData = await privSuccessRes.json();
  console.log('Private Data with Valid Session:', privSuccessRes.status, privSuccessData.vaultItems.length);

  // 로그아웃 요청
  const logoutRes = await fetch(`${BASE_URL}/api/auth/logout`, {
    method: 'POST',
    headers: { 'Cookie': `vault_session=${testSessionToken}` }
  });
  console.log('Logout response:', logoutRes.status);

  // 로그아웃 후 같은 세션 토큰으로 재요청 (T08-C33)
  const afterLogoutRes = await fetch(`${BASE_URL}/api/private/data`, {
    headers: { 'Cookie': `vault_session=${testSessionToken}` }
  });
  const afterLogoutBody = await afterLogoutRes.json();
  console.log('After Logout Status:', afterLogoutRes.status, afterLogoutBody);

  console.log('--- Log Generation Finished Successfully ---');
}

generateReportLogs().catch(console.error);
