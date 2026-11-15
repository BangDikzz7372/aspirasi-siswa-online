
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

function response(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

function randomCode(length = 12) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));

  return Array.from(bytes, b => chars[b % chars.length]).join("");
}

async function hashPin(pin) {
  const data = new TextEncoder().encode(pin);
  const hash = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  if (a.length !== b.length) return false;

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // STATUS BACKEND
    if (url.pathname === "/api/status" && request.method === "GET") {
      return response({
        success: true,
        project: "Aspirasi Siswa Online",
        status: "Backend aktif",
        version: "1.2.0"
      });
    }

    // KIRIM ASPIRASI
    if (
      url.pathname === "/api/aspirations" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();

        const category = String(body.category || "").trim();
        const title = String(body.title || "").trim();
        const content = String(body.content || "").trim();
        const senderName = String(body.sender_name || "").trim();
        const isAnonymous = body.is_anonymous !== false;

        const allowedCategories = ["Kritik", "Saran", "Ide"];

        if (!allowedCategories.includes(category)) {
          return response({
            success: false,
            message: "Kategori tidak valid."
          }, 400);
        }

        if (title.length < 3 || title.length > 120) {
          return response({
            success: false,
            message: "Judul harus 3–120 karakter."
          }, 400);
        }

        if (content.length < 10 || content.length > 3000) {
          return response({
            success: false,
            message: "Isi harus 10–3000 karakter."
          }, 400);
        }

        if (senderName.length > 80) {
          return response({
            success: false,
            message: "Nama terlalu panjang."
          }, 400);
        }

        const trackingCode = randomCode(12);
        const pin = randomCode(8);
        const pinHash = await hashPin(pin);

        await env.DB.prepare(`
          INSERT INTO aspirations
          (tracking_code, pin_hash, category, title, content,
           sender_name, is_anonymous)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(
          trackingCode,
          pinHash,
          category,
          title,
          content,
          isAnonymous ? null : senderName,
          isAnonymous ? 1 : 0
        ).run();

        return response({
          success: true,
          message: "Aspirasi berhasil dikirim.",
          tracking_code: trackingCode,
          pin: pin,
          note: "Simpan kode dan PIN ini dengan aman."
        }, 201);

      } catch (error) {
        return response({
          success: false,
          message: "Gagal menyimpan aspirasi."
        }, 500);
      }
    }

    // PELACAKAN ASPIRASI
    if (
      url.pathname === "/api/track" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();

        const trackingCode = String(
          body.tracking_code || ""
        ).trim().toUpperCase();

        const pin = String(body.pin || "").trim().toUpperCase();

        if (
          !/^[A-HJ-NP-Z2-9]{12}$/.test(trackingCode) ||
          !/^[A-HJ-NP-Z2-9]{8}$/.test(pin)
        ) {
          return response({
            success: false,
            message: "Kode pelacakan atau PIN tidak valid."
          }, 400);
        }

        const aspiration = await env.DB.prepare(`
          SELECT id, tracking_code, category, title, content,
                 sender_name, is_anonymous, status,
                 created_at, updated_at, pin_hash
          FROM aspirations
          WHERE tracking_code = ?
        `).bind(trackingCode).first();

        if (!aspiration) {
          return response({
            success: false,
            message: "Kode pelacakan atau PIN salah."
          }, 401);
        }

        const enteredHash = await hashPin(pin);

        if (!safeEqual(enteredHash, aspiration.pin_hash)) {
          return response({
            success: false,
            message: "Kode pelacakan atau PIN salah."
          }, 401);
        }

        const messages = await env.DB.prepare(`
          SELECT sender_type, message, visibility, created_at
          FROM aspiration_messages
          WHERE aspiration_id = ?
          ORDER BY created_at ASC, id ASC
        `).bind(aspiration.id).all();

        return response({
          success: true,
          message: "Aspirasi berhasil ditemukan.",
          aspiration: {
            tracking_code: aspiration.tracking_code,
            category: aspiration.category,
            title: aspiration.title,
            content: aspiration.content,
            sender_name: aspiration.sender_name,
            is_anonymous: Boolean(aspiration.is_anonymous),
            status: aspiration.status,
            created_at: aspiration.created_at,
            updated_at: aspiration.updated_at
          },
          replies: messages.results || []
        });

      } catch (error) {
        return response({
          success: false,
          message: "Terjadi kesalahan saat melacak aspirasi."
        }, 500);
      }
    }

    return response({
      success: false,
      message: "Endpoint tidak ditemukan."
    }, 404);
  }
};
                          
