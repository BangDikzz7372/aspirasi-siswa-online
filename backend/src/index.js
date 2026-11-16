
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers":
    "Content-Type, Authorization, X-Admin-Setup-Key"
};

const PBKDF2_ITERATIONS = 100000;
const SESSION_HOURS = 12;

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

function randomBytesHex(length = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, b =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

function randomCode(length = 12) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, b =>
    chars[b % chars.length]
  ).join("");
}

async function sha256(value) {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(hash), b =>
    b.toString(16).padStart(2, "0")
  ).join("");
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

async function hashPassword(password) {
  const salt = randomBytesHex(16);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  const hash = Array.from(new Uint8Array(bits), b =>
    b.toString(16).padStart(2, "0")
  ).join("");

  return `pbkdf2$${PBKDF2_ITERATIONS}$${salt}$${hash}`;
}

async function verifyPassword(password, stored) {
  try {
    const [algorithm, iterationsText, salt, expected] =
      stored.split("$");

    if (algorithm !== "pbkdf2") return false;

    const iterations = Number(iterationsText);

    if (
      !Number.isInteger(iterations) ||
      iterations < 100000 ||
      iterations > 1000000
    ) {
      return false;
    }

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: new TextEncoder().encode(salt),
        iterations,
        hash: "SHA-256"
      },
      key,
      256
    );

    const actual = Array.from(new Uint8Array(bits), b =>
      b.toString(16).padStart(2, "0")
    ).join("");

    return safeEqual(actual, expected);
  } catch {
    return false;
  }
}

async function getAdmin(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer ([a-f0-9]{64})$/i);

  if (!match) return null;

  const tokenHash = await sha256(match[1]);

  const session = await env.DB.prepare(`
    SELECT admins.id, admins.username
    FROM admin_sessions
    JOIN admins ON admins.id = admin_sessions.admin_id
    WHERE admin_sessions.token_hash = ?
      AND admin_sessions.expires_at > CURRENT_TIMESTAMP
  `).bind(tokenHash).first();

  return session || null;
}

async function hashPin(pin) {
  return sha256(pin);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // STATUS BACKEND
      if (path === "/api/status" && method === "GET") {
        return response({
          success: true,
          project: "Aspirasi Siswa Online",
          status: "Backend aktif",
          version: "2.0.0"
        });
      }

      // PEMBUATAN ADMIN PERTAMA
      if (path === "/api/admin/setup" && method === "POST") {
        const setupKey = request.headers.get("X-Admin-Setup-Key");

        if (
          !env.ADMIN_SETUP_KEY ||
          !safeEqual(setupKey, env.ADMIN_SETUP_KEY)
        ) {
          return response({
            success: false,
            message: "Kunci setup tidak valid."
          }, 403);
        }

        const body = await request.json();
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        if (!/^[a-zA-Z0-9_.-]{3,30}$/.test(username)) {
          return response({
            success: false,
            message: "Username harus 3–30 karakter dan hanya boleh berisi huruf, angka, titik, garis bawah, atau tanda hubung."
          }, 400);
        }

        if (password.length < 12 || password.length > 128) {
          return response({
            success: false,
            message: "Password harus 12–128 karakter."
          }, 400);
        }

        const passwordHash = await hashPassword(password);

        const result = await env.DB.prepare(`
          INSERT INTO admins (username, password_hash)
          SELECT ?, ?
          WHERE NOT EXISTS (SELECT 1 FROM admins)
        `).bind(username, passwordHash).run();

        if (!result.meta || result.meta.changes !== 1) {
          return response({
            success: false,
            message: "Admin pertama sudah dibuat atau username tidak dapat digunakan."
          }, 409);
        }

        return response({
          success: true,
          message: "Admin pertama berhasil dibuat. Silakan login."
        }, 201);
      }

      // LOGIN ADMIN
      if (path === "/api/admin/login" && method === "POST") {
        const body = await request.json();
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        if (!username || !password || password.length > 128) {
          return response({
            success: false,
            message: "Username atau password salah."
          }, 401);
        }

        const admin = await env.DB.prepare(`
          SELECT id, username, password_hash
          FROM admins
          WHERE username = ?
        `).bind(username).first();

        if (
          !admin ||
          !(await verifyPassword(password, admin.password_hash))
        ) {
          return response({
            success: false,
            message: "Username atau password salah."
          }, 401);
        }

        const token = randomBytesHex(32);
        const tokenHash = await sha256(token);

        await env.DB.prepare(`
          DELETE FROM admin_sessions
          WHERE expires_at <= CURRENT_TIMESTAMP
        `).run();

        await env.DB.prepare(`
          INSERT INTO admin_sessions
          (admin_id, token_hash, expires_at)
          VALUES (?, ?, datetime('now', '+12 hours'))
        `).bind(admin.id, tokenHash).run();

        return response({
          success: true,
          message: "Login berhasil.",
          token,
          expires_in: SESSION_HOURS * 60 * 60,
          admin: {
            id: admin.id,
            username: admin.username
          }
        });
      }

      // PERIKSA SESI ADMIN
      if (path === "/api/admin/me" && method === "GET") {
        const admin = await getAdmin(request, env);

        if (!admin) {
          return response({
            success: false,
            message: "Sesi tidak valid atau sudah berakhir."
          }, 401);
        }

        return response({
          success: true,
          admin: {
            id: admin.id,
            username: admin.username
          }
        });
      }

      // LOGOUT ADMIN
      if (path === "/api/admin/logout" && method === "POST") {
        const authorization = request.headers.get("Authorization") || "";
        const match = authorization.match(/^Bearer ([a-f0-9]{64})$/i);

        if (match) {
          const tokenHash = await sha256(match[1]);

          await env.DB.prepare(`
            DELETE FROM admin_sessions
            WHERE token_hash = ?
          `).bind(tokenHash).run();
        }

        return response({
          success: true,
          message: "Logout berhasil."
        });
      }

      // KIRIM ASPIRASI
      if (path === "/api/aspirations" && method === "POST") {
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
          pin,
          note: "Simpan kode dan PIN ini dengan aman."
        }, 201);
      }

      // PELACAKAN ASPIRASI
      if (path === "/api/track" && method === "POST") {
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
            AND visibility = 'public'
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
      }

// ==========================================
// ADMIN: DAFTAR ASPIRASI
// ==========================================
if (
  url.pathname === "/api/admin/aspirations" &&
  request.method === "GET"
) {
  const admin = await getAdmin(request, env);

  if (!admin) {
    return response({
      success: false,
      message: "Sesi admin tidak valid atau sudah berakhir."
    }, 401);
  }

  const allowedStatuses = [
    "Menunggu",
    "Dibaca",
    "Diproses",
    "Selesai"
  ];

  
const status = url.searchParams.get("status");
const requestedPage = Number.parseInt(
  url.searchParams.get("page") || "1",
  10
);

const page = Math.min(
  100000,
  Math.max(1, Number.isSafeInteger(requestedPage) ? requestedPage : 1)
);

const limit = Math.min(
  50,
  Math.max(
    1,
    Number.parseInt(url.searchParams.get("limit") || "20", 10) || 20
  )
);
  

  if (status && !allowedStatuses.includes(status)) {
    return response({
      success: false,
      message: "Filter status tidak valid."
    }, 400);
  }

  const offset = (page - 1) * limit;

  let query = `
    SELECT
      id,
      tracking_code,
      category,
      title,
      sender_name,
      is_anonymous,
      status,
      is_published,
      created_at,
      updated_at
    FROM aspirations
  `;

  const values = [];

  if (status) {
    query += " WHERE status = ?";
    values.push(status);
  }

  query += `
    ORDER BY created_at DESC, id DESC
    LIMIT ? OFFSET ?
  `;

  values.push(limit, offset);

  const result = await env.DB
    .prepare(query)
    .bind(...values)
    .all();

  let countQuery = "SELECT COUNT(*) AS total FROM aspirations";
  const countValues = [];

  if (status) {
    countQuery += " WHERE status = ?";
    countValues.push(status);
  }

  const countResult = await env.DB
    .prepare(countQuery)
    .bind(...countValues)
    .first();

  return response({
    success: true,
    message: "Daftar aspirasi berhasil ditemukan.",
    pagination: {
      page,
      limit,
      total: countResult.total,
      total_pages: Math.ceil(countResult.total / limit)
    },
    aspirations: result.results
  });
}
      
// DETAIL ASPIRASI ADMIN
const detailMatch = url.pathname.match(
  /^\/api\/admin\/aspirations\/(\d+)$/
);

if (detailMatch && request.method === "GET") {
  const admin = await getAdmin(request, env);

  if (!admin) {
    return response({
      success: false,
      message: "Sesi admin tidak valid atau sudah berakhir."
    }, 401);
  }

  const aspirationId = Number(detailMatch[1]);

  if (!Number.isSafeInteger(aspirationId) || aspirationId < 1) {
    return response({
      success: false,
      message: "ID aspirasi tidak valid."
    }, 400);
  }

  const aspiration = await env.DB.prepare(`
    SELECT
      id,
      tracking_code,
      category,
      title,
      content,
      sender_name,
      is_anonymous,
      status,
      is_published,
      created_at,
      updated_at
    FROM aspirations
    WHERE id = ?
  `).bind(aspirationId).first();

  if (!aspiration) {
    return response({
      success: false,
      message: "Aspirasi tidak ditemukan."
    }, 404);
  }

  const messages = await env.DB.prepare(`
    SELECT
      id,
      sender_type,
      message,
      visibility,
      created_at
    FROM aspiration_messages
    WHERE aspiration_id = ?
    ORDER BY created_at ASC, id ASC
  `).bind(aspirationId).all();

  return response({
    success: true,
    message: "Detail aspirasi berhasil ditemukan.",
    aspiration,
    replies: messages.results
  });
}
      
// UPDATE STATUS ASPIRASI ADMIN
const statusMatch = url.pathname.match(
  /^\/api\/admin\/aspirations\/(\d+)\/status$/
);

if (statusMatch && request.method === "POST") {
  const admin = await getAdmin(request, env);

  if (!admin) {
    return response({
      success: false,
      message: "Sesi admin tidak valid atau sudah berakhir."
    }, 401);
  }

  const aspirationId = Number(statusMatch[1]);

  if (!Number.isSafeInteger(aspirationId) || aspirationId < 1) {
    return response({
      success: false,
      message: "ID aspirasi tidak valid."
    }, 400);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return response({
      success: false,
      message: "Format JSON tidak valid."
    }, 400);
  }

  const allowedStatuses = [
    "Menunggu",
    "Dibaca",
    "Diproses",
    "Selesai"
  ];

  if (!allowedStatuses.includes(body.status)) {
    return response({
      success: false,
      message: "Status aspirasi tidak valid."
    }, 400);
  }

  const existing = await env.DB.prepare(`
    SELECT id
    FROM aspirations
    WHERE id = ?
  `).bind(aspirationId).first();

  if (!existing) {
    return response({
      success: false,
      message: "Aspirasi tidak ditemukan."
    }, 404);
  }

  await env.DB.prepare(`
    UPDATE aspirations
    SET
      status = ?,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).bind(body.status, aspirationId).run();

  return response({
    success: true,
    message: "Status aspirasi berhasil diperbarui.",
    aspiration_id: aspirationId,
    status: body.status
  });
}
      
// BALAS ASPIRASI ADMIN
const replyMatch = url.pathname.match(
  /^\/api\/admin\/aspirations\/(\d+)\/reply$/
);

if (replyMatch && request.method === "POST") {
  const admin = await getAdmin(request, env);

  if (!admin) {
    return response({
      success: false,
      message: "Sesi admin tidak valid atau sudah berakhir."
    }, 401);
  }

  const aspirationId = Number(replyMatch[1]);

  if (!Number.isSafeInteger(aspirationId) || aspirationId < 1) {
    return response({
      success: false,
      message: "ID aspirasi tidak valid."
    }, 400);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return response({
      success: false,
      message: "Format JSON tidak valid."
    }, 400);
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return response({
      success: false,
      message: "Format data tidak valid."
    }, 400);
  }

  const message =
    typeof body.message === "string"
      ? body.message.trim()
      : "";

  const visibility = body.visibility;

  if (message.length < 1 || message.length > 3000) {
    return response({
      success: false,
      message: "Balasan harus berisi 1 sampai 3000 karakter."
    }, 400);
  }

  if (!["public", "private"].includes(visibility)) {
    return response({
      success: false,
      message: "Jenis visibilitas tidak valid."
    }, 400);
  }

  const existing = await env.DB.prepare(`
    SELECT id
    FROM aspirations
    WHERE id = ?
  `).bind(aspirationId).first();

  if (!existing) {
    return response({
      success: false,
      message: "Aspirasi tidak ditemukan."
    }, 404);
  }

  const result = await env.DB.prepare(`
    INSERT INTO aspiration_messages (
      aspiration_id,
      sender_type,
      message,
      visibility
    )
    VALUES (?, 'admin', ?, ?)
  `).bind(
    aspirationId,
    message,
    visibility
  ).run();

  await env.DB.prepare(`
    UPDATE aspirations
    SET updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).bind(aspirationId).run();

  return response({
    success: true,
    message: "Balasan aspirasi berhasil dikirim.",
    reply_id: result.meta.last_row_id,
    aspiration_id: aspirationId,
    visibility: visibility
  });
}
    
      // PUBLIKASI ASPIRASI ADMIN
      const publishMatch = url.pathname.match(
        /^\/api\/admin\/aspirations\/(\d+)\/publish$/
      );

      if (publishMatch && request.method === "POST") {
        const admin = await getAdmin(request, env);

        if (!admin) {
          return response({
            success: false,
            message: "Sesi admin tidak valid atau sudah berakhir."
          }, 401);
        }

        const aspirationId = Number(publishMatch[1]);

        if (!Number.isSafeInteger(aspirationId) || aspirationId < 1) {
          return response({
            success: false,
            message: "ID aspirasi tidak valid."
          }, 400);
        }

        let body;

        try {
          body = await request.json();
        } catch {
          return response({
            success: false,
            message: "Format JSON tidak valid."
          }, 400);
        }

        if (
          !body ||
          typeof body !== "object" ||
          Array.isArray(body)
        ) {
          return response({
            success: false,
            message: "Format data tidak valid."
          }, 400);
        }

        if (![0, 1].includes(body.is_published)) {
          return response({
            success: false,
            message: "Nilai publikasi harus 0 atau 1."
          }, 400);
        }

        const existing = await env.DB.prepare(`
          SELECT id
          FROM aspirations
          WHERE id = ?
        `).bind(aspirationId).first();

        if (!existing) {
          return response({
            success: false,
            message: "Aspirasi tidak ditemukan."
          }, 404);
        }

        await env.DB.prepare(`
          UPDATE aspirations
          SET
            is_published = ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).bind(
          body.is_published,
          aspirationId
        ).run();

        return response({
          success: true,
          message: body.is_published === 1
            ? "Aspirasi berhasil dipublikasikan."
            : "Publikasi aspirasi berhasil dinonaktifkan.",
          aspiration_id: aspirationId,
          is_published: body.is_published
        });
      }
      // DAFTAR PENGUMUMAN ADMIN
if (
  url.pathname === "/api/admin/announcements" &&
  request.method === "GET"
) {
  const admin = await getAdmin(request, env);

  if (!admin) {
    return response({
      success: false,
      message: "Sesi admin tidak valid atau sudah berakhir."
    }, 401);
  }

  const result = await env.DB.prepare(`
    SELECT
      id,
      title,
      content,
      is_published,
      created_at
    FROM announcements
    ORDER BY created_at DESC, id DESC
  `).all();

  return response({
    success: true,
    message: "Daftar pengumuman berhasil ditemukan.",
    announcements: result.results
  });
}
    
      
      
      
      
      return response({
        success: false,
        message: "Endpoint tidak ditemukan."
      }, 404);

    } catch (error) {
  console.error("BACKEND ERROR:", error);

  return response({
    success: false,
    message: "Terjadi kesalahan pada server."
  }, 500);
    }
  }
};
                        
