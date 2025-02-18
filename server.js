require("dotenv").config();
const express = require("express");
const db = require("./db");
const bcrypt = require("bcrypt");
const cors = require("cors");
const app = express();
const PORT = process.env.PORT;

app.use(express.json());
app.use(cors());
app.get("/questions", (req, res) => {
  const sql = "SELECT * FROM questions";
  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const checkUserQuery = "SELECT * FROM users WHERE email = ?";
    db.query(checkUserQuery, [email], async (err, results) => {
      if (err) return res.status(500).json({ error: err.message });

      if (results.length > 0) {
        return res.status(400).json({ error: "Email already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const insertUserQuery =
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
      db.query(
        insertUserQuery,
        [name, email, hashedPassword],
        (err, result) => {
          if (err) return res.status(500).json({ error: err.message });

          res.status(201).json({
            message: "User registered successfully",
            userId: result.insertId,
          });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/signin", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const checkUserQuery = "SELECT * FROM users WHERE email = ?";
  db.query(checkUserQuery, [email], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    if (results.length === 0) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    res.status(200).json({
      message: "Signin successful",
      username: user.name,
      user_id: user.id,
    });
  });
});
app.post("/saveData", (req, res) => {
  const { user_id, username, words, score, question_id, total } = req.body;

  const checkUserQuery = "SELECT * FROM users WHERE id = ?";
  db.query(checkUserQuery, [user_id], (err, userResults) => {
    if (err) return res.status(500).json({ error: err.message });

    if (!userResults.length) {
      return res.status(400).json({ error: "User not found" });
    }

    const checkQuestionQuery = "SELECT * FROM questions WHERE id = ?";
    db.query(checkQuestionQuery, [question_id], (err, questionResults) => {
      if (err) return res.status(500).json({ error: err.message });

      const checkScoreQuery =
        "SELECT * FROM scores WHERE user_id = ? AND question_id = ?";
      db.query(checkScoreQuery, [user_id, question_id], (err, scoreResults) => {
        if (err) return res.status(500).json({ error: err.message });

        if (scoreResults.length > 0) {
          return res
            .status(400)
            .json({ error: "Cannot Attend the same question again" });
        }

        const insertScoreQuery =
          "INSERT INTO scores (user_id, question_id, username, words, score, total) VALUES (?, ?, ?, ?, ?, ?)";
        db.query(
          insertScoreQuery,
          [user_id, question_id, username, JSON.stringify(words), score, total],
          (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json({
              message: "Sucessfully Submitted",
              scoreId: result.insertId,
            });
          }
        );
      });
    });
  });
});
app.get("/getUserData", (req, res) => {
  const getAllScoresQuery = "SELECT * FROM scores";
  db.query(getAllScoresQuery, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) {
      return res.status(404).json({ message: "No Data found" });
    }
    res.status(200).json(results);
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
