export const config = {
  matcher: '/:path*',
};

export default async function middleware(request) {
  const redisUrl = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const redisToken = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  const cookieName = 'site_auth_forever';
  const url = new URL(request.url);

  // 1. Keep them logged in forever (10 years) if cookie is present
  const cookies = request.headers.get('cookie') || '';
  if (cookies.includes(`${cookieName}=granted`)) {
    return;
  }

  let error = '';
  if (request.method === 'POST' && redisUrl && redisToken) {
    const formData = await request.formData();
    const mode = formData.get('mode');

    // MODE A: Claim a one-time invite code and set a permanent personal password
    if (mode === 'claim') {
      const inviteCode = (formData.get('invite_code') || '').trim();
      const personalPass = (formData.get('personal_pass') || '').trim();

      if (inviteCode && personalPass.length >= 4) {
        const existsRes = await fetch(`${redisUrl}/sismember/user_passwords/${encodeURIComponent(personalPass)}`, {
          headers: { Authorization: `Bearer ${redisToken}` },
        });
        const existsData = await existsRes.json();

        if (existsData.result === 1) {
          error = "<p style='color: #d93025; margin-top: 10px;'>That personal password is already taken. Pick another!</p>";
        } else {
          const burnRes = await fetch(`${redisUrl}/srem/valid_passwords/${encodeURIComponent(inviteCode)}`, {
            headers: { Authorization: `Bearer ${redisToken}` },
          });
          const burnData = await burnRes.json();

          if (burnData.result === 1) {
            await fetch(`${redisUrl}/sadd/user_passwords/${encodeURIComponent(personalPass)}`, {
              headers: { Authorization: `Bearer ${redisToken}` },
            });

            return new Response(null, {
              status: 302,
              headers: {
                Location: url.pathname,
                'Set-Cookie': `${cookieName}=granted; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=315360000`,
              },
            });
          } else {
            error = "<p style='color: #d93025; margin-top: 10px;'>Invalid or already used invite code.</p>";
          }
        }
      } else {
        error = "<p style='color: #d93025; margin-top: 10px;'>Personal password must be at least 4 characters.</p>";
      }
    }

    // MODE B: Returning visitor logging back in after clearing cookies
    if (mode === 'login') {
      const personalPass = (formData.get('personal_pass') || '').trim();
      if (personalPass) {
        const checkRes = await fetch(`${redisUrl}/sismember/user_passwords/${encodeURIComponent(personalPass)}`, {
          headers: { Authorization: `Bearer ${redisToken}` },
        });
        const checkData = await checkRes.json();

        if (checkData.result === 1) {
          return new Response(null, {
            status: 302,
            headers: {
              Location: url.pathname,
              'Set-Cookie': `${cookieName}=granted; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=315360000`,
            },
          });
        }
      }
      error = "<p style='color: #d93025; margin-top: 10px;'>Incorrect personal password.</p>";
    }
  }

  // 3. Login & Invite Claim Screen
  const html = `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Member Access</title>
    <style>
      body { font-family: system-ui, sans-serif; display: grid; place-items: center; min-height: 100vh; margin: 0; background: #f4f4f9; }
      .card { background: white; padding: 2rem; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 320px; text-align: center; }
      input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ccc; border-radius: 5px; box-sizing: border-box; }
      button { width: 100%; padding: 10px; margin-top: 8px; background: #000; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 15px; }
      button:hover { background: #333; }
      hr { margin: 1.5rem 0; border: none; border-top: 1px solid #eee; }
      h3 { margin: 0 0 8px 0; font-size: 16px; }
      p.sub { font-size: 12px; color: #666; margin: 0 0 10px 0; }
    </style>
  </head>
  <body>
    <div class="card">
      ${error}
      <form method="POST">
        <h3>First Time? Claim Invite</h3>
        <p class="sub">Enter your one-time invite code and create a personal password so you never get locked out.</p>
        <input type="hidden" name="mode" value="claim" />
        <input type="text" name="invite_code" placeholder="One-time invite code" required />
        <input type="password" name="personal_pass" placeholder="Create personal password" required />
        <button type="submit">Claim & Unlock Forever</button>
      </form>

      <hr />

      <form method="POST">
        <h3>Returning Member?</h3>
        <p class="sub">Cleared cookies or new device? Log back in anytime.</p>
        <input type="hidden" name="mode" value="login" />
        <input type="password" name="personal_pass" placeholder="Your personal password" required />
        <button type="submit">Log Back In</button>
      </form>
    </div>
  </body>
  </html>`;

  return new Response(html, {
    status: 401,
    headers: { 'Content-Type': 'text/html' },
  });
}
