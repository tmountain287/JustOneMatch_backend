import { onRequest } from "firebase-functions/v2/https";
import * as logger from "firebase-functions/logger";
import { defineSecret } from "firebase-functions/params";
import { google } from "googleapis";
import { OAuth2Client } from "google-auth-library";

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
// Google Play 결제 검증
// ----------------------
export const verifyPurchase = onRequest(
    { secrets: [GP_JSON] },
    async (req, res) => {
        try {
            const { packageName, productId, purchaseToken } = req.body ?? {};

            if (!packageName || !productId || !purchaseToken) {
                res.status(400).json({ error: "Missing parameters" });
                return;
            }

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

            res.json({
                status: "ok",
                purchase: result.data,
            });

        } catch (error: any) {
            logger.error("verifyPurchase error:", error);
            res.status(500).json({ error: "Server error", details: error?.message });
        }
    }
);
