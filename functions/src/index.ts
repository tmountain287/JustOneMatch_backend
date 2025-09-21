import { onRequest, Request } from 'firebase-functions/v2/https';
import type { Response } from 'express';
import { defineSecret } from 'firebase-functions/params';
import * as admin from 'firebase-admin';
import { OAuth2Client } from 'google-auth-library';
import cors from 'cors';
import { google } from "googleapis"; // package.json에 googleapis 이미 있음

admin.initializeApp();

const corsHandler = cors({ origin: true });

const WEB_CLIENT_ID = defineSecret('GOOGLE_WEB_CLIENT_ID');
const ALLOWED_AUDS = defineSecret('GOOGLE_ALLOWED_AUDS');
const GP_JSON = defineSecret('GP_SERVICE_ACCOUNT_JSON');

function decodeJwtPayload(idToken: string): Record<string, any> | null {
    try {
        const seg = idToken.split('.')[1];
        if (!seg) return null;
        const b64 = seg.replace(/-/g, '+').replace(/_/g, '/');
        const pad = b64 + '==='.slice((b64.length + 3) % 4);
        return JSON.parse(Buffer.from(pad, 'base64').toString('utf8'));
    } catch {
        return null;
    }
}

// -----------------------------
// 1) 구글 ID 토큰 검증 엔드포인트
// -----------------------------
export const verifyGoogleIdToken = onRequest(
    { secrets: [WEB_CLIENT_ID, ALLOWED_AUDS] },
    async (req: Request, res: Response): Promise<void> => {
        corsHandler(req, res, async () => {
            if (req.method === 'OPTIONS') {
                res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
                res.set('Access-Control-Allow-Headers', 'Content-Type, x-id-token');
                res.status(204).send('');
                return;
            }
            if (req.method !== 'POST') {
                res.status(405).json({ error: 'Method Not Allowed' });
                return;
            }

            const headerToken = req.headers['x-id-token'];
            const idToken =
                (req.body && (req.body.idToken as unknown)) ??
                (Array.isArray(headerToken) ? headerToken[0] : headerToken);

            if (!idToken || typeof idToken !== 'string') {
                res.status(400).json({ error: 'Missing idToken' });
                return;
            }

            const allowedAudiences = ((ALLOWED_AUDS.value() || WEB_CLIENT_ID.value() || '')
                .split(',')
                .map((s) => s.trim())
                .filter(Boolean));

            if (allowedAudiences.length === 0) {
                res.status(500).json({
                    error:
                        'No audience configured. Set GOOGLE_WEB_CLIENT_ID or GOOGLE_ALLOWED_AUDS.',
                });
                return;
            }

            const raw = decodeJwtPayload(idToken);
            if (raw) {
                console.log('[verifyGoogleIdToken] incoming aud/iss', {
                    aud: raw.aud,
                    iss: raw.iss,
                    azp: raw.azp,
                });
            }

            try {
                const client = new OAuth2Client();
                const ticket = await client.verifyIdToken({
                    idToken,
                    audience: allowedAudiences,
                });

                const payload = ticket.getPayload();
                if (!payload) {
                    res.status(401).json({ error: 'Invalid token payload' });
                    return;
                }

                const { sub, email, email_verified, iss, aud, name, picture } = payload;

                if (!(iss === 'accounts.google.com' || iss === 'https://accounts.google.com')) {
                    res.status(401).json({ error: 'Invalid issuer' });
                    return;
                }
                if (!allowedAudiences.includes(String(aud))) {
                    res.status(401).json({
                        error: 'Invalid audience',
                        details: `aud=${aud}, allowed=${allowedAudiences.join(',')}`,
                    });
                    return;
                }
                if (email && email_verified === false) {
                    res.status(401).json({ error: 'Email not verified' });
                    return;
                }

                let firebaseCustomToken: string | null = null;
                if (sub) {
                    try {
                        firebaseCustomToken = await admin.auth().createCustomToken(sub, {
                            email: email || '',
                            provider: 'google',
                        });
                    } catch (e: any) {
                        console.warn('Custom token create failed (optional): ' + e.message);
                    }
                }

                res.json({
                    ok: true,
                    googleUser: { uid: sub, email, name, picture },
                    firebaseCustomToken,
                });
                return;
            } catch (err: any) {
                res.status(401).json({
                    error: 'Invalid Google ID Token',
                    details: err?.message || String(err),
                });
                return;
            }
        });
    },
);

type VerifyBody = {
  packageName: string;         // 예: com.yourcompany.yourgame
  productId?: string;          // 일회성(In-app) 상품 ID
  subscriptionId?: string;     // 구독 상품 ID
  purchaseToken: string;       // BillingClient 결제 토큰
  acknowledge?: boolean;       // 검증 후 서버에서 승인까지 할지(기본 false)
  developerPayload?: string;   // (선택) 개발자 데이터 비교용
};

function getAuthFromServiceAccountJson(jsonStr: string) {
  // 서비스계정 JSON을 직접 문자열로 받아 auth 객체 생성
  const creds = JSON.parse(jsonStr);
  const auth = new google.auth.JWT({
    email: creds.client_email,
    key: creds.private_key,
    scopes: ["https://www.googleapis.com/auth/androidpublisher"],
  });
  return auth;
}

// -----------------------------
// 2) 결제 검증 엔드포인트 (자리만 유지)
// -----------------------------
export const verifyPurchase = onRequest(
  { secrets: [GP_JSON] },
  async (req: Request, res: Response): Promise<void> => {
    corsHandler(req, res, async () => {
      if (req.method === "OPTIONS") {
        res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
        res.set("Access-Control-Allow-Headers", "Content-Type");
        res.status(204).send("");
        return;
      }
      if (req.method !== "POST") {
        res.status(405).json({ error: "Method Not Allowed" });
        return;
      }

      // 입력 파싱
      const body = req.body as VerifyBody;
      const { packageName, productId, subscriptionId, purchaseToken, acknowledge, developerPayload } =
        body || ({} as VerifyBody);

      if (!packageName || !purchaseToken || (!productId && !subscriptionId)) {
        res.status(400).json({
          error: "Missing fields",
          required: "packageName, purchaseToken, and (productId or subscriptionId)",
        });
        return;
      }

      const svcJson = GP_JSON.value();
      if (!svcJson) {
        res.status(500).json({ error: "Missing GP_SERVICE_ACCOUNT_JSON secret" });
        return;
      }

      try {
        const auth = getAuthFromServiceAccountJson(svcJson);
        const androidpublisher = google.androidpublisher({ version: "v3", auth });

        if (productId) {
          // ==============================
          // ❶ 일회성(In-app) 상품 검증
          // ==============================
          const getResp = await androidpublisher.purchases.products.get({
            packageName,
            productId,
            token: purchaseToken,
          });

          const data = getResp.data; // https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.products
          // 주요 필드: purchaseState, consumptionState, acknowledgementState, orderId, purchaseTimeMillis, developerPayload

          // (선택) 개발자페이로드 검증
          if (developerPayload && data.obfuscatedExternalAccountId !== undefined) {
            // Billing v5+는 developerPayload 직접 제공 안 함. 필요 시 클라이언트에서 setObfuscatedAccountId/ObfuscatedProfileId 사용해 비교.
          }

          const acknowledged = data.acknowledgementState === 1;
          const purchased = data.purchaseState === 0; // 0=purchased, 1=canceled, 2=pending

          // 필요하면 여기서 DB에 영수증/유저 지급 기록 저장…

          // 승인(acknowledge) 옵션 처리
          if (acknowledge && purchased && !acknowledged) {
            try {
              await androidpublisher.purchases.products.acknowledge({
                packageName,
                productId,
                token: purchaseToken,
                requestBody: { developerPayload: developerPayload ?? "" },
              });
            } catch (ackErr: any) {
              // 이미 승인된 경우 등은 무시 가능
              console.warn("acknowledge error:", ackErr?.message || String(ackErr));
            }
          }

          res.status(200).json({
            ok: purchased,
            type: "inapp",
            productId,
            orderId: data.orderId,
            purchaseState: data.purchaseState,
            acknowledgementState: data.acknowledgementState,
            consumptionState: data.consumptionState,
            purchaseTimeMillis: data.purchaseTimeMillis,
            kind: data.kind,
          });
          return;
        } else {
          // ==============================
          // ❷ 구독(Subscription) 검증
          // ==============================
          // v3에서는 purchases.subscriptions.get / purchases.subscriptionsv2.get 둘 중 하나 사용
          // 여기선 v3 기존 엔드포인트 사용(단순)
          const subId = String(subscriptionId);
          const getResp = await androidpublisher.purchases.subscriptions.get({
            packageName,
            subscriptionId: subId,
            token: purchaseToken,
          });

          const data = getResp.data; // https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.subscriptions
          // 주요 필드: expiryTimeMillis, autoRenewing, paymentState, cancelReason, linkedPurchaseToken, orderId, acknowledgementState

          const acknowledged = (data as any).acknowledgementState === 1; // 일부 필드는 v3 스키마에서 optional
          const active = !!data.expiryTimeMillis && Number(data.expiryTimeMillis) > Date.now();

          if (acknowledge && !acknowledged) {
            try {
              await androidpublisher.purchases.subscriptions.acknowledge({
                packageName,
                subscriptionId: subId,
                token: purchaseToken,
                requestBody: { developerPayload: developerPayload ?? "" },
              });
            } catch (ackErr: any) {
              console.warn("subscription acknowledge error:", ackErr?.message || String(ackErr));
            }
          }

          res.status(200).json({
            ok: active,
            type: "subs",
            subscriptionId: subId,
            orderId: data.orderId,
            expiryTimeMillis: data.expiryTimeMillis,
            autoRenewing: data.autoRenewing,
            paymentState: (data as any).paymentState, // 1=Payment received
            cancelReason: data.cancelReason,          // 0=user, 1=system, 2=replaced, 3=developer
            acknowledgementState: (data as any).acknowledgementState,
          });
          return;
        }
      } catch (e: any) {
        console.error("verifyPurchase error:", e?.message || String(e));
        res.status(500).json({
          error: "verifyPurchase failed",
          details: e?.message || String(e),
        });
        return;
      }
    });
  }
);
