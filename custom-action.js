/**
* Handler that will be called during the execution of a PostLogin flow.
*/
const ManagementClient = require('auth0').ManagementClient;

exports.onExecutePostLogin = async (event, api) => {
  // Management API の初期化（Secrets に登録した値を使用）
  const management = new ManagementClient({
    domain: event.secrets.AUTH0_DOMAIN,
    clientId: event.secrets.AUTH0_CLIENT_ID,
    clientSecret: event.secrets.AUTH0_CLIENT_SECRET,
  });

  // 1. 接続種別の判定
  const enterpriseStrategies = ["waad", "samlp", "oidc", "adfs"];
  const isEnterprise = enterpriseStrategies.includes(event.connection.strategy);

  // --- A. Enterprise接続（isEnterprise: true）の場合のロジック ---
  if (isEnterprise) {
    const rawFlag = event.user.app_metadata?.is_pre_provisioned;
    const isPreProvisioned = (rawFlag === "true" || rawFlag === true);

    // 事前登録フラグがない場合はアクセス拒否 ＆ アカウント削除
    if (!isPreProvisioned) {
      try {
        await management.users.delete({ id: event.user.user_id });
        console.log(`[Security] Deleted enterprise user ${event.user.user_id} due to missing SCIM flag.`);
      } catch (err) {
        console.error("[Security] Failed to delete user:", err.message);
      }
      return api.access.deny("access_denied", "事前登録されていないエンタープライズユーザーです。管理者に連絡してください。");
    }

  } 
  
  // --- B. DB接続（isEnterprise: false）の場合のロジック ---
  else {
    // すでにこのセッションで MFA (email) を完了しているか確認
    const mfaDone = event.authentication?.methods.some(method => method.name === 'mfa' && method.type === 'email');

    if (!mfaDone) {
      // まだMFAしていない場合のみ、MFAを有効化してチャレンジを要求
      api.multifactor.enable('any');
      api.authentication.challengeWith({ type: 'email' });
    }
    // すでに完了している場合は、何もしない（＝そのままアプリへ通す）
  }

  // --- C. 共通：Roleチェック（Client ID と同名の Role が必要） ---
  const currentClientId = event.client.client_id;
  const userRoles = event.authorization?.roles || [];
  const hasRequiredRole = userRoles.includes(currentClientId);

  if (!hasRequiredRole) {
    // Enterprise ユーザーかつ Role がない場合も、ゴミを残さないために削除を実行
    if (isEnterprise) {
      try {
        await management.users.delete({ id: event.user.user_id });
        console.log(`[Security] Deleted enterprise user ${event.user.user_id} due to missing Role.`);
      } catch (err) {
        console.error("[Security] Failed to delete user with no role:", err.message);
      }
    }
    
    return api.access.deny("access_denied", "このアプリケーションへのアクセス権限（Role）がありません。");
  }
};