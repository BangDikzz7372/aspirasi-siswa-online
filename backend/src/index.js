
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
      "Content-Type": "application/json"
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (url.pathname === "/api/status" && request.method === "GET") {
      return response({
        success: true,
        project: "Aspirasi Siswa Online",
        status: "Backend aktif",
        version: "1.1.0"
      });
    }

    if (url.pathname === "/api/aspirations" && request.method === "POST") {
      try {
        const body = await request.json();

        const category = String(body.category || "").trim();
        const title = String(body.title || "").trim();
        const content = String(body.content || "").trim();
        const senderName = String(body.sender_name || "").trim();
        const isAnonymous = body.is_anonymous !== false;

        const allowedCategories = ["Kritik", "Saran", "Ide"];

        if (!allowedCategories.includes(category)) {
          return response({ success: false, message: "Kategori tidak valid." }, 400);
        }

        if (title.length < 3 || title.length > 120) {
          return response({ success: false, message: "Judul harus 3–120 karakter." }, 400);
        }

        if (content.length < 10 || content.length > 3000) {
          return response({ success: false, message: "Isi harus 10–3000 karakter." }, 400);
        }

        if (senderName.length > 80) {
          return response({ success: false, message: "Nama terlalu panjang." }, 400);
        }

        const trackingCode = randomCode(12);
        const pin = randomCode(8);
        const pinHash = await hashPin(pin);

        await env.DB.prepare(`
          INSERT INTO aspirations
          (tracking_code, pin_hash, category, title, content, sender_name, is_anonymous)
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
          note: "Simpan kode pelacakan dan PIN ini. PIN tidak dapat ditampilkan kembali."
        }, 201);

      } catch (error) {
        return response({
          success: false,
          message: "Gagal menyimpan aspirasi."
        }, 500);
      }
    }

    return response({
      success: false,
      message: "Endpoint tidak ditemukan."
    }, 404);
  }
};
