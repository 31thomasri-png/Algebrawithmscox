export const config = {
  matcher: '/:path*',
};

export default async function middleware(request) {
  const password = 'SneakiestLemon73';
  const cookieName = 'site_auth';
  const url = new URL(request.url);

  // 1. Allow access if the visitor already has the valid cookie
  const cookies = request.headers.get('cookie') || '';
  if (cookies.includes(`${cookieName}=${password}`)) {
    return;
  }

  // 2. Check password if the form was just submitted
  let error = '';
  if (request.method === 'POST') {
    const formData = await request.formData();
    if (formData.get('password') === password) {
      return new Response(null, {
        status: 302,
        headers: {
          Location: url.pathname,
          'Set-Cookie': `${cookieName}=${password}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`,
        },
      });
    }
    error = "<p style='color: #d93025; margin-top: 10px;'>Incorrect password. Try again.</p>";
  }

  // 3. Otherwise, show the password prompt
  const html = `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Required</title>
    <style>
      body { font-family: system-ui, sans-serif; display: grid; place-items: center; height: 100vh; margin: 0; background: #f4f4f9; }
      form { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; width: 300px; }
      input { width: 100%; padding: 10px; margin: 12px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
      button { width: 100%; padding: 10px; background: #000; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
      button:hover { background: #333; }
    </style>
  </head>
  <body>
    <form method="POST">
      <h2>Protected Site</h2>
      <input type="password" name="password" placeholder="Enter password" required autofocus />
      <button type="submit">Unlock</button>
      ${error}
    </form>
  </body>
  </html>`;

  return new Response(html, {
    status: 401,
    headers: { 'Content-Type': 'text/html' },
  });
}
