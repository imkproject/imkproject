const COOKIE="__Host-imk_session", enc=new TextEncoder();
const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...headers}});
const rand=n=>{let a=new Uint8Array(n);crypto.getRandomValues(a);return a};
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
const sha=async s=>hex(await crypto.subtle.digest("SHA-256",enc.encode(s)));
const token=b=>btoa(String.fromCharCode(...b)).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
async function passHash(password,salt){let key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);let saltBytes=Uint8Array.from(salt.match(/../g).map(x=>parseInt(x,16)));return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt:saltBytes,iterations:310000,hash:"SHA-256"},key,256))}
function cookie(t,exp){return `${COOKIE}=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${new Date(exp*1000).toUTCString()}`}
async function captcha(tokenValue,req,env){if(!tokenValue||!env.TURNSTILE_SECRET_KEY)return false;let f=new FormData();f.set("secret",env.TURNSTILE_SECRET_KEY);f.set("response",tokenValue);let ip=req.headers.get("CF-Connecting-IP");if(ip)f.set("remoteip",ip);try{return (await (await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify",{method:"POST",body:f})).json()).success===true}catch{return false}}
function originOK(req,env){let o=req.headers.get("Origin");try{return !!o&&(new URL(o).host===new URL(req.url).host||o===env.ALLOWED_ORIGIN)}catch{return false}}
async function currentUser(req,env){let c=req.headers.get("Cookie")||"",m=c.match(/(?:^|;\s*)__Host-imk_session=([^;]+)/);if(!m)return null;let h=await sha(m[1]),now=Math.floor(Date.now()/1000);let u=await env.DB.prepare("SELECT users.id,users.username,users.email,sessions.expires_at FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=?").bind(h).first();if(!u||u.expires_at<now){if(u)await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(h).run();return null}return {id:u.id,username:u.username,email:u.email}}
async function newSession(id,env){let t=token(rand(32)),exp=Math.floor(Date.now()/1000)+604800;await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(await sha(t),id,exp).run();return cookie(t,exp)}
async function handle(req,env){let p=new URL(req.url).pathname;
 if(req.method==="GET"&&p==="/api/me")return json({user:await currentUser(req,env)});
 if(req.method!=="POST"||!["/api/register","/api/login","/api/logout"].includes(p))return json({error:"Не найдено"},404);
 if(!originOK(req,env))return json({error:"Недопустимый источник запроса"},403);
 if(p==="/api/logout"){let c=req.headers.get("Cookie")||"",m=c.match(/(?:^|;\s*)__Host-imk_session=([^;]+)/);if(m)await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha(m[1])).run();return json({ok:true},200,{"set-cookie":`${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`})}
 let data;try{data=await req.json()}catch{return json({error:"Некорректный запрос"},400)}
 if(!await captcha(data.captcha,req,env))return json({error:"CAPTCHA не пройдена. Повторите попытку."},400);
 let pw=String(data.password||"");if(pw.length<8||pw.length>128)return json({error:"Пароль должен содержать от 8 до 128 символов"},400);
 if(p==="/api/register"){let username=String(data.username||"").trim(),email=String(data.email||"").trim().toLowerCase();if(!/^[A-Za-z0-9_]{3,24}$/.test(username))return json({error:"Логин: 3–24 символа, латиница, цифры и _"},400);if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254)return json({error:"Введите корректную почту"},400);
 let exists=await env.DB.prepare("SELECT id FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE").bind(username,email).first();if(exists)return json({error:"Логин или почта уже заняты"},409);
 let salt=hex(rand(16)),hash=await passHash(pw,salt),res;try{res=await env.DB.prepare("INSERT INTO users(username,email,password_hash,password_salt,created_at) VALUES(?,?,?,?,?)").bind(username,email,hash,salt,Math.floor(Date.now()/1000)).run()}catch{return json({error:"Не удалось создать аккаунт"},409)}
 let set=await newSession(res.meta.last_row_id,env);return json({ok:true,user:{username,email}},200,{"set-cookie":set})}
 let identity=String(data.identity||"").trim(),u=await env.DB.prepare("SELECT id,username,email,password_hash,password_salt FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE").bind(identity,identity.toLowerCase()).first();if(!u||await passHash(pw,u.password_salt)!==u.password_hash)return json({error:"Неверный логин, почта или пароль"},401);
 let set=await newSession(u.id,env);return json({ok:true,user:{username:u.username,email:u.email}},200,{"set-cookie":set})
}
export async function onRequest({request,env}){return handle(request,env)}
