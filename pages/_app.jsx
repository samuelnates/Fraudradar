import Head from "next/head";
import "../styles/globals.css";

export default function App({ Component, pageProps }) {
  return (
    <>
      <Head>
        <title>FraudRadar.io — Detección de Fraude en Datos Financieros</title>
        <meta name="description" content="Análisis forense estadístico de tus datos financieros. La misma metodología utilizada por la SEC, el IRS y el SAT. $5.00 USD por análisis." />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta property="og:title" content="FraudRadar.io — Detección de Fraude Financiero" />
        <meta property="og:description" content="Detecta anomalías en tus datos financieros en segundos. Metodología forense de nivel institucional." />
        <meta property="og:url" content="https://fraudradar.io" />
        <meta property="og:type" content="website" />
        <meta name="twitter:card" content="summary_large_image" />
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </Head>
      <Component {...pageProps} />
    </>
  );
}
