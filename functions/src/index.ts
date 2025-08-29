import { onRequest } from "firebase-functions/v2/https";
import { defineSecret } from "firebase-functions/params";
import * as admin from "firebase-admin";
import { OAuth2Client } from "google-auth-library";
import corsLib = require("cors");

admin.initializeApp();

const cors = corsLib({ origin: true });

// ✅ 구글 ID 토큰 검증에 필요한 허용 audience 설정 (웹 클라이언트 ID 권장)
const WEB_CLIENT_ID = defineSecret("GOOGLE_WEB_CLIENT_ID");   // 예: 1234-xxxx.apps.googleusercontent.com
const ALLOWED_AUDS = defineSecret("GOOGLE_ALLOWED_AUDS");      // 선택: 쉼표로 여러 개 허용

// (선택) 결제 검증용 서비스계정 JSON
const GP_JSON = defineSecret("GP_SERVICE_ACCOUNT_JSON");

// JWT payload 디버그용
function decodeJwtPayload(idToken: string): any | null {
    try {
        const seg = idToken.split(".")[1];
        if (!seg) return null;
        const b64 = seg.replace(/-/g, "+").replace(/_/g, "/");
        const pad = b64 + "===".slice((b64.length + 3) % 4);
        return JSON.parse(Buffer.from(pad, "base64").toString("utf8"));
    } catch {
        return null;
    }
}

// -----------------------------
// 1) ✅ 구글 ID 토큰 검증 엔드포인트
// -----------------------------
export const verifyGoogleIdToken = onRequest(
    { secrets: [WEB_CLIENT_ID, ALLOWED_AUDS] },
    async (req, res) => {
        return cors(req, res, async () => {
            if (req.method === "OPTIONS") {
                res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
                res.set("Access-Control-Allow-Headers", "Content-Type, x-id-token");
                return res.status(204).send("");
            }
            if (req.method !== "POST") return res.status(405).json({ error: "Method Not Allowed" });

            const idToken = (req.body && req.body.idToken) || req.headers["x-id-token"];
            if (!idToken) return res.status(400).json({ error: "Missing idToken" });

            // 허용 audience 셋업 (GOOGLE_ALLOWED_AUDS가 있으면 우선)
            const allowedAudiences = (
                (ALLOWED_AUDS.value() || WEB_CLIENT_ID.value() || "")
                    .split(",")
                    .map(s => s.trim())
                    .filter(Boolean)
            );

            if (allowedAudiences.length === 0) {
                return res.status(500).json({
                    error: "No audience configured. Set GOOGLE_WEB_CLIENT_ID or GOOGLE_ALLOWED_AUDS."
                });
            }

            // 디버깅: 들어온 토큰의 aud/iss 확인
            const raw = decodeJwtPayload(String(idToken));
            if (raw) {
                console.log("[verifyGoogleIdToken] incoming aud/iss", { aud: raw.aud, iss: raw.iss, azp: raw.azp });
            }

            try {
                const client = new OAuth2Client();
                const ticket = await client.verifyIdToken({
                    idToken: String(idToken),
                    audience: allowedAudiences, // ★ 구글 ID 토큰의 aud가 여기 목록 중 하나와 일치해야 함
                });

                const payload = ticket.getPayload();
                if (!payload) return res.status(401).json({ error: "Invalid token payload" });

                const { sub, email, email_verified, iss, aud, name, picture } = payload;

                // issuer 확인 (구글 ID 토큰)
                if (!(iss === "accounts.google.com" || iss === "https://accounts.google.com")) {
                    return res.status(401).json({ error: "Invalid issuer" });
                }
                // audience 최종 확인
                if (!allowedAudiences.includes(String(aud))) {
                    return res.status(401).json({
                        error: "Invalid audience",
                        details: `aud=${aud}, allowed=${allowedAudiences.join(",")}`
                    });
                }
                if (email && email_verified === false) {
                    return res.status(401).json({ error: "Email not verified" });
                }

                // (선택) Firebase 커스텀 토큰 발급 — 파이어베이스 세션을 쓰고 싶을 때만
                let firebaseCustomToken: string | null = null;
                if (sub) {
                    try {
                        firebaseCustomToken = await admin.auth().createCustomToken(sub, {
                            email: email || "",
                            provider: "google",
                        });
                    } catch (e: any) {
                        console.warn("Custom token create failed (optional): " + e.message);
                    }
                }

                return res.json({
                    ok: true,
                    googleUser: { uid: sub, email, name, picture },
                    firebaseCustomToken, // 필요 없으면 무시
                });
            } catch (err: any) {
                return res.status(401).json({
                    error: "Invalid Google ID Token",
                    details: err?.message || String(err),
                });
            }
        });
    }
);

// -----------------------------
// 2) (참고) 결제 검증 엔드포인트 그대로 유지
// -----------------------------
export const verifyPurchase = onRequest(
    { secrets: [GP_JSON] },
    async (req, res) => {
        // ... (기존 코드 그대로)
        return res.status(501).json({ error: "keep your existing verifyPurchase code here" });
    }
);
