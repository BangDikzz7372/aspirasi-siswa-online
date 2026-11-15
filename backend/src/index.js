
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/status") {
      return Response.json({
        success: true,
        project: "Aspirasi Siswa Online",
        status: "Backend aktif",
        version: "1.0.0"
      });
    }

    return Response.json({
      success: true,
      message: "Aspirasi Siswa API"
    });
  }
};
