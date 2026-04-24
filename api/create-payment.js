// api/create-payment.js
// Backend seguro — crea el PaymentIntent de Stripe
// Vercel convierte este archivo en: https://fraudradar.io/api/create-payment

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: 500, // $5.00 USD en centavos
      currency: "usd",
      automatic_payment_methods: { enabled: true },
      metadata: {
        product: "fraudradar_analysis",
        version: "1.0",
      },
    });

    res.status(200).json({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    console.error("Stripe error:", error);
    res.status(500).json({ error: error.message });
  }
}
