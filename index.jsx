export default function Home() {
  return (
    <div style={{
      background: "#080c14",
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      fontFamily: "sans-serif"
    }}>
      <div style={{ textAlign: "center" }}>
        <h1 style={{ color: "#3b82f6", fontSize: 48, margin: 0 }}>
          Fraud<span style={{ color: "#f1f5f9" }}>Radar</span>
          <span style={{ color: "#475569", fontSize: 20 }}>.io</span>
        </h1>
        <p style={{ color: "#475569", marginTop: 16 }}>
          Sitio en construcción — volvemos pronto
        </p>
      </div>
    </div>
  );
}
