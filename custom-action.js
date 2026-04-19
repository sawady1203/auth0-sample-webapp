/**
* Handler that will be called during the execution of a PostLogin flow.
*/
const ManagementClient = require('auth0').ManagementClient;

exports.onExecutePostLogin = async (event, api) => {
  const management = new ManagementClient({
    domain: event.secrets.AUTH0_DOMAIN,
    clientId: event.secrets.AUTH0_CLIENT_ID,
    clientSecret: event.secrets.AUTH0_CLIENT_SECRET,
  });

  // --- 1. 共通情報の取得 ---
  const enterpriseStrategies = ["waad", "samlp", "oidc", "adfs"];
  const isEnterprise = enterpriseStrategies.includes(event.connection.strategy);
  const currentClientId = event.client.client_id;

  // アプリケーションの Metadata から要求される認証レベルを取得 (GUIで設定する値)
  // 設定がない場合はデフォルトでレベル 2 (Email MFA) とします
  const requiredLevel = parseInt(event.client.metadata?.required_auth_level || "2", 10);

  // --- 2. Enterprise接続専用のチェック (事前登録フラグ) ---
  if (isEnterprise) {
    const rawFlag = event.user.app_metadata?.is_pre_provisioned;
    const isPreProvisioned = (rawFlag === "true" || rawFlag === true);

    if (!isPreProvisioned) {
      try {
        await management.users.delete({ id: event.user.user_id });
        console.log(`[Security] Deleted Enterprise user ${event.user.user_id}: No SCIM flag.`);
      } catch (err) {
        console.error("[Security] Delete failed:", err.message);
      }
      return api.access.deny("access_denied", "事前登録されていないエンタープライズユーザーです。");
    }

    // フラグを Boolean に正規化（運用を楽にするため）
    if (typeof rawFlag === "string") {
      api.user.setAppMetadata("is_pre_provisioned", true);
    }
  }

  // --- 3. ステップアップ MFA ロジック (DBユーザー対象) ---
  // Enterprise ユーザーも一貫した強度を求めるなら !isEnterprise の条件を外してもOKです
  if (!isEnterprise) {
    // 現在のセッションですでに完了している認証方法を確認
    const methods = event.authentication?.methods || [];
    const hasEmailMfa = methods.some(m => m.name === 'mfa' && m.type === 'email');
    const hasStrongMfa = methods.some(m => m.name === 'mfa' && (m.type === 'webauthn' || m.type === 'otp'));

    let currentLevel = 1; // デフォルト（パスワードのみ）
    if (hasStrongMfa) {
      currentLevel = 3;
    } else if (hasEmailMfa) {
      currentLevel = 2;
    }

    // 要求レベルに達していない場合のみ MFA を実行
    if (currentLevel < requiredLevel) {
      if (requiredLevel === 2) {
        // レベル 2: Email OTP を強制
        api.multifactor.enable('any');
        api.authentication.challengeWith({ type: 'email' });
      } else if (requiredLevel >= 3) {
        // レベル 3: 強固な MFA (WebAuthn/アプリ等) を要求
        // 特定のタイプを指定しないことで、登録済みの最強要素が呼ばれます
        api.multifactor.enable('any');
      }
    }
  }

  // --- 4. 共通：Roleチェック (Client ID と同名の Role が必要) ---
  const userRoles = event.authorization?.roles || [];
  const hasRequiredRole = userRoles.includes(currentClientId);

  if (!hasRequiredRole) {
    // Enterprise ユーザーの場合は Role がなくてもゴミを残さないために削除
    if (isEnterprise) {
      try {
        await management.users.delete({ id: event.user.user_id });
      } catch (err) {
        console.error("[Security] Delete failed (No Role):", err.message);
      }
    }
    return api.access.deny("access_denied", "このアプリケーションへのアクセス権限(Role)がありません。");
  }
};