const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: 500, currency: "usd",
      automatic_payment_methods: { enabled: true },
      metadata: { product: "fraudradar_analysis" },
    });
    res.status(200).json({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}
