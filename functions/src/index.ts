import { onRequest } from "firebase-functions/v2/https";
import * as logger from "firebase-functions/logger";
import { defineSecret } from "firebase-functions/params";
import { google } from "googleapis";
import { OAuth2Client } from "google-auth-library";

import * as admin from "firebase-admin";
admin.initializeApp();
const db = admin.firestore();

/**
 * ============================
 *  Secret Manager (필요한 1개만)
 * ============================
 * Google Play 결제 검증용 서비스 계정 JSON
 */
const GP_JSON = defineSecret("GP_SERVICE_ACCOUNT_JSON");



/**
 * ============================
 *  Google Login Audience 설정
 * ============================
 * 이 값들은 비밀이 아니며 앱에도 포함되는 공개 정보임.
 * → Secret Manager에서 제거 가능
 */
const WEB_CLIENT_ID =
    "788294993689-oqhpc6hpcj6utskqe9k45jk8illfp0i6.apps.googleusercontent.com";

const ANDROID_CLIENT_ID_1 =
    "788294993689-5egq6j9j2dk5ahovvnjc1lsf5v0kl6q8.apps.googleusercontent.com";

const ANDROID_CLIENT_ID_2 =
    "788294993689-dndcr4urbm4244ke9hluvulsfkmuo510.apps.googleusercontent.com";

const ALLOWED_AUDIENCES = [
    WEB_CLIENT_ID,
    ANDROID_CLIENT_ID_1,
    ANDROID_CLIENT_ID_2,
];




// ----------------------
// Google Login 검증
// ----------------------
export const verifyGoogleIdToken = onRequest(async (req, res) => {
    try {
        const token = req.body?.idToken;

        if (!token) {
            res.status(400).json({ ok: false, error: "Missing idToken" });
            return;
        }

        const client = new OAuth2Client();
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: ALLOWED_AUDIENCES,
        });

        const payload = ticket.getPayload();

        if (!payload) {
            res.status(401).json({ ok: false, error: "Invalid token" });
            return;
        }

        // 로그인 성공
        res.json({
            ok: true,
            userId: payload.sub,
            email: payload.email,
            name: payload.name,
            picture: payload.picture,
        });
    } catch (error: any) {
        logger.error("verifyGoogleIdToken error:", error);
        res
            .status(500)
            .json({ ok: false, error: error?.message ?? "Server error" });
    }
});




// ----------------------
// Google Play 결제 검증 + 로그 저장
// ----------------------
export const verifyPurchase = onRequest(
    { secrets: [GP_JSON] },
    async (req, res) => {
        try {
            const { packageName, productId, purchaseToken, accountId } = req.body ?? {};

            if (!packageName || !productId || !purchaseToken) {
                res.status(400).json({ error: "Missing parameters" });
                return;
            }

            // accountId는 저장용이므로 없으면 "unknown" 처리 (원하면 400으로 막아도 됨)
            const safeAccountId =
                typeof accountId === "string" && accountId.length > 0
                    ? accountId
                    : "unknown";

            const svcJson = GP_JSON.value();
            if (!svcJson) {
                res.status(500).json({ error: "Missing GP_SERVICE_ACCOUNT_JSON" });
                return;
            }

            const serviceAccount = JSON.parse(svcJson);

            const auth = new google.auth.GoogleAuth({
                credentials: serviceAccount,
                scopes: ["https://www.googleapis.com/auth/androidpublisher"],
            });

            const androidpublisher = google.androidpublisher({
                version: "v3",
                auth,
            });

            const result = await androidpublisher.purchases.products.get({
                packageName,
                productId,
                token: purchaseToken,
            });

            // ✅ 여기서부터 로그 저장
            const p = result.data;

            // purchaseState: 0 = Purchased
            const purchaseState = typeof p.purchaseState === "number" ? p.purchaseState : -1;

            // orderId는 없을 수도 있음(테스트/환경/상품 유형에 따라)
            const orderId = (p.orderId ?? "") as string;

            // 구매 시간(밀리초 문자열로 올 때가 많음)
            const purchaseTimeMillisRaw = (p.purchaseTimeMillis ?? "") as string;
            const purchaseTimeMillis =
                typeof purchaseTimeMillisRaw === "string" && purchaseTimeMillisRaw.length > 0
                    ? Number(purchaseTimeMillisRaw)
                    : null;

            // 멱등키: purchaseToken(가장 흔히 씀)
            const docId = purchaseToken;

            const logRef = db.collection("iap_purchases").doc(docId);

            // 서버시간/클라시간 둘 다 보관 추천
            const now = admin.firestore.FieldValue.serverTimestamp();

            await logRef.set(
                {
                    // 검색용 필드들
                    accountId: safeAccountId,
                    packageName,
                    productId,
                    purchaseToken,
                    orderId,

                    // 검증 결과 요약
                    purchaseState,
                    acknowledgementState: p.acknowledgementState ?? null,
                    consumptionState: p.consumptionState ?? null,
                    kind: p.kind ?? null,

                    // 시간
                    purchaseTimeMillis: purchaseTimeMillis,
                    verifiedAt: now,

                    // 원본(필요한 경우만) — 너무 크면 빼도 됨
                    purchaseRaw: p,
                },
                { merge: true }
            );

            res.json({
                ok: true,
                status: "ok",
                purchase: p,
                logged: true,
                logDocId: docId,
            });
        } catch (error: any) {
            logger.error("verifyPurchase error:", error);
            res.status(500).json({ error: "Server error", details: error?.message });
        }
    }
);
