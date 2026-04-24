# FraudRadar.io

Detección forense de anomalías en datos financieros.  
Metodología estadística de nivel institucional · $5.00 USD por análisis.

## Stack

- **Next.js 14** — frontend + API routes
- **Stripe** — procesamiento de pagos
- **Vercel** — hosting y deploy

## Deploy rápido

### 1. Clona o sube a GitHub

```bash
git init
git add .
git commit -m "FraudRadar v1.0"
git remote add origin https://github.com/TU_USUARIO/fraudradar.git
git push -u origin main
```

### 2. Deploy en Vercel

1. Ve a vercel.com/new
2. Conecta el repositorio de GitHub
3. En **Environment Variables** agrega:

| Variable | Valor |
|---|---|
| `STRIPE_SECRET_KEY` | `sk_test_...` o `sk_live_...` |
| `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` | `pk_test_...` o `pk_live_...` |

4. Click **Deploy** — listo en ~2 minutos

### 3. Dominio personalizado

En Vercel → Settings → Domains → agrega `fraudradar.io`  
Configura los DNS en tu registrador según las instrucciones de Vercel.

## Desarrollo local

```bash
# Instala dependencias
npm install

# Crea tu archivo de variables
cp .env.local.example .env.local
# Edita .env.local con tus llaves de Stripe

# Corre en local
npm run dev
# → http://localhost:3000
```

## Tarjeta de prueba Stripe

```
Número: 4242 4242 4242 4242
Fecha:  cualquier fecha futura (ej. 12/26)
CVV:    cualquier 3 dígitos (ej. 123)
```

## Video

Cuando tengas el video de CapCut/HeyGen, súbelo como:
```
public/fraudradar-explainer-es.mp4
public/fraudradar-explainer-en.mp4
```
Y actualiza `VIDEO_SRC` en `pages/index.jsx`.

## Contacto

contacto@fraudradar.io
