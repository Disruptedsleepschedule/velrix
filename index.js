require("dotenv").config();

const express = require("express");
const OpenAI = require("openai");

const app = express();
const PORT = process.env.PORT || 3000;

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    agent: "Velrix",
    agentId: 96147,
    network: "Base",
    status: "online",
    ai: true
  });
});

app.post("/chat", async (req, res) => {
  try {
    const message = req.body.message;

    if (!message) {
      return res.status(400).json({
        error: "message is required"
      });
    }

    const response = await openai.responses.create({
      model: "gpt-6-astra",
      instructions:
        "You are Velrix, an autonomous AI agent registered as ERC-8004 Agent #96147 on Base. Be concise, useful, and clear.",
      input: message
    });

    res.json({
      agent: "Velrix",
      response: response.output_text
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Velrix AI request failed"
    });
  }
});

app.listen(PORT, () => {
  console.log(`Velrix is running at http://localhost:${PORT}`);
});