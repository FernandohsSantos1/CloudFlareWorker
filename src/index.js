import { SignJWT, jwtVerify } from 'jose';

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const { pathname, hostname } = url;

		if (pathname === "/fingerprint.js" && request.method === "GET") {
			const script = `
			  (async function(){
				function getFingerprint(){
					const { href } = window.location

					return {
						method: 'GET',
						path: href,
						userAgent: navigator.userAgent,
						language: navigator.language,
						screen: { width: screen.width, height: screen.height },
						timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
					};
				}

				const fingerprint = getFingerprint();
				try {
					const res = await fetch("https://${hostname}/api/fingerprint", {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify(fingerprint)
					})
				} catch(e){
					console.log(e)
				}
			  })();
			`;
			return new Response(script, {
				headers: {
					"Content-Type": "application/javascript",
				  	"Access-Control-Allow-Origin": "*"
			   }
			});
		}


		if (pathname === '/api/fingerprint' && request.method === 'OPTIONS') {
			try {
				return new Response(null, {
					status: 204,
					headers: {
					  "Access-Control-Allow-Origin": "*",
					  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
					  "Access-Control-Allow-Headers": "Content-Type",
					  "Access-Control-Max-Age": "86400"
					}
				  });
			} catch (err) {
				return new Response(JSON.stringify({ success: false, error: err.toString() }), { status: 500 });
			}
		}

		if (pathname === '/api/fingerprint' && request.method === 'POST') {
			try {
				console.log(request)

				const data = await request.json();

				console.log(data)

				await env.DB.prepare(
					`
						INSERT INTO logs (method, path, user_agent, language, screen_width, screen_height, timezone, created_at)
						VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
					`
					)
					.bind(data.method, data.path, data.userAgent, data.language, data.screen.width, data.screen.height, data.timezone)
					.run();

				return new Response(JSON.stringify({ success: true }), {
					headers: {
						'Content-Type': 'application/json',
						'Access-Control-Allow-Origin': '*'
				 } });
			} catch (err) {
				return new Response(JSON.stringify({ success: false, error: err.toString() }), { status: 500 });
			}
		}

		if (pathname === '/logs' && request.method === 'GET') {
			const cookieJWT = getCookie(request, 'token');

			if (!cookieJWT) {
				return new Response(renderLoginPage("", "É necessário estar autenticado. Por favor, faça o login para continuar..."), { headers: { "Content-Type": "text/html" } });
			}
			try {
				await jwtVerify(cookieJWT, new TextEncoder().encode(env.JWT_SECRET), {
					algorithms: ["HS256"]
				});

				const { results } = await env.DB.prepare(`SELECT * FROM logs ORDER BY created_at DESC`).all();
				return new Response(renderLogsPage(results), { headers: { 'Content-Type': 'text/html' } });
			} catch (e) {
				return new Response(renderLoginPage("", "É necessário estar autenticado. Por favor, faça o login para continuar..."), { headers: { "Content-Type": "text/html" } });
			}
		}

		if (pathname === '/login' && request.method === 'GET') {
			return new Response(renderLoginPage(), { headers: { 'Content-Type': 'text/html' } });
		}

		if (pathname === '/login' && request.method === 'POST') {
			const formData = await request.formData();
			const username = formData.get('email');
			const password = formData.get('password');
			const { results } = await env.DB.prepare(`SELECT * FROM users WHERE email = ? AND password = ?`)
				.bind(username, password)
				.run();

			if (!!results.length) {
				const token = await createJWT(results[0].name, env.JWT_SECRET);

				return new Response('Login realizado com sucesso. Redirecionando...', {
					status: 302,
					headers: {
						'Set-Cookie': `token=${token}; HttpOnly; Path=/;`,
						'Location': '/logs'
					},
				});
			}

			return new Response(renderLoginPage("Usuário não encontrado"), {
				headers: { 'Content-Type': 'text/html' },
			});
		}

		if	(pathname === '/announcement' && request.method === 'GET') {
			return new Response(renderAdPage(), { headers: { 'Content-Type': 'text/html' } });
		}

		if (request.method === 'GET') {
			return new Response(null, { status: 302, headers: { "Location": "/announcement" } });
		}

		return new Response('Página não encontrada', { status: 404 });
	},
}

async function createJWT(username, secret) {
	const token = await new SignJWT({ username })
		.setProtectedHeader({ alg: "HS256" })
		.setIssuedAt()
		.setExpirationTime("1h")
		.sign(new TextEncoder().encode(secret));

	return token;
}

function getCookie(request, name) {
	const cookie = request.headers.get('Cookie');
	if (!cookie) return null;
	const parts = cookie.split(';').map((c) => c.trim());
	for (const part of parts) {
		const [key, value] = part.split('=');
		if (key === name) return value;
	}
	return null;
}

function renderAdPage() {
	return `
	<!DOCTYPE html>
		<html>
			<meta charset="utf-8">
			<title>Anúncio de Produto</title>
		<style>
		body {
			font-family: sans-serif;
			margin: 0;
			padding: 0;
			background-color: #f9f9f9;
			display: flex;
			align-items: center;
			justify-content: center;
			min-height: 100vh;
		}
		.container {
			max-width: 600px;
			background: #fff;
			padding: 2rem;
			border-radius: 8px;
			box-shadow: 0 2px 8px rgba(0,0,0,0.1);
			text-align: center;
		}
		h1 {
			margin-bottom: 1rem;
		}
		.product-image {
			max-width: 100%;
			height: auto;
			margin-bottom: 1rem;
		}
		.description {
			margin-bottom: 1.5rem;
		}
		#status {
			margin-top: 1rem;
			color: #2d862d;
			font-weight: bold;
		}
		</style>
	</head>
	<body>
		<div class="container">
			<h1>Bem-vindo ao anúncio do Produto X</h1>
			<img src="data:image/png;base64,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" alt="Imagem do Produto" class="product-image" />
			<p class="description">
				Este é um produto genérico incrível que pode ajudar você de diversas formas.
				Confira as vantagens e aproveite!
			</p>
			</div>
			<script src="https://cloud-flare-challenge.fingerprinttest.workers.dev/fingerprint.js"></script>
		</body>
	</html>
	`;
}

function renderLoginPage(errorMessage = "", alertMessage = "") {
	return `
	<!DOCTYPE html>
		<html>
		<head>
			<meta charset="utf-8">
			<title>Login</title>
			<style>
				body {
				font-family: sans-serif;
				margin: 0;
				padding: 0;
				background-color: #f5f5f5;
				display: flex;
				align-items: center;
				justify-content: center;
				height: 100vh;
				}
				.container {
				width: 100%;
				max-width: 400px;
				background: #fff;
				padding: 2rem;
				box-shadow: 0 2px 10px rgba(0,0,0,0.1);
				border-radius: 8px;
				}
				h2 {
				text-align: center;
				}
				input, button {
				width: 100%;
				padding: 0.5rem;
				margin-bottom: 1rem;
				box-sizing: border-box;
				}
				.error {
				color: red;
				text-align: center;
				margin-bottom: 1rem;
				}
				.alert {
				position:absolute;
				background-color: #ffcccc;
				border: 1px solid #ff8888;
				padding: 1rem;
				text-align: center;
				margin-bottom: 1rem;
				border-radius: 4px;
				font-weight: bold;
				top: 5%;
				}
			</style>
		</head>
		<body>
		${alertMessage ? `<div class="alert">${alertMessage}</div>` : ""}
		<div class="container">
			<h2>Login</h2>
			<form method="POST" action="/login">
			<input type="text" name="email" placeholder="Email" required>
			<input type="password" name="password" placeholder="Password" required>
			${errorMessage ? `<p class="error">${errorMessage}</p>` : ""}
			<button type="submit">Entrar</button>
			</form>
		</div>
    	</body>
	</html>
	`;
}

function renderLogsPage(logs) {
	let rows = logs.map((log) => `
		<tr>
			<td>${log.id || '-'}</td>
			<td>${log.method || '-'}</td>
			<td>${log.path || '-'}</td>
			<td>${log.user_agent || '-'}</td>
			<td>${log.language || '-'}</td>
			<td>${log.screen_width}x${log.screen_height}</td>
			<td>${log.timezone || '-'}</td>
			<td>${log.created_at || '-'}</td>
		</tr>
	`
		)
		.join('');
	return `
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="utf-8">
			<title>Logs de Acesso</title>
			<style>
			body { font-family: sans-serif; margin: 2rem; }
			table { width: 100%; border-collapse: collapse; }
			th, td { border: 1px solid #ccc; padding: 0.5rem; text-align: left; }
			th { background: #f4f4f4; }
			</style>
		</head>
		<body>
			<h1>Logs de Acesso</h1>
			<table>
			<thead>
				<tr>
					<th>ID</th>
					<th>Método</th>
					<th>Caminho</th>
					<th>User Agent</th>
					<th>Idioma</th>
					<th>Resolução</th>
					<th>Fuso</th>
					<th>Data</th>
				</tr>
			</thead>
			<tbody>
				${rows}
			</tbody>
			</table>
		</body>
		</html>
	`;
}
