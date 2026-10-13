
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const pool = require("./db");

const app = express();
const PORT = 3000;

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: false,
            maxAge: 1000 * 60 * 60 * 2
        }
    })
);

// Require a signed-in user for protected routes.
function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect("/login");
    }

    next();
}

// HOME: display posts from PostgreSQL.
app.get("/", async (req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT blog_id, creator_name, creator_user_id,
                    title, body, date_created
             FROM blogs
             ORDER BY date_created DESC, blog_id DESC`
        );

        res.render("index", {
            posts: result.rows,
            user: req.session.user || null,
            message: req.query.message || ""
        });
    } catch (error) {
        next(error);
    }
});

// SIGNUP PAGE
app.get("/signup", (req, res) => {
    res.render("signup", { error: "" });
});

// REGISTER A USER
app.post("/signup", async (req, res, next) => {
    const userId = (req.body.user_id || "").trim();
    const name = (req.body.name || "").trim();
    const password = req.body.password || "";

    if (!userId || !name || !password) {
        return res.status(400).render("signup", {
            error: "Please fill in every field."
        });
    }

    if (userId.length > 255 || name.length > 255) {
        return res.status(400).render("signup", {
            error: "User ID and name must be 255 characters or fewer."
        });
    }

    if (password.length < 8 || Buffer.byteLength(password, "utf8") > 72) {
        return res.status(400).render("signup", {
            error: "Password must be at least 8 characters and no more than 72 bytes."
        });
    }

    try {
        const existing = await pool.query(
            "SELECT user_id FROM users WHERE user_id = $1",
            [userId]
        );

        if (existing.rows.length > 0) {
            return res.status(409).render("signup", {
                error: "That user ID is already taken. Please choose another."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        await pool.query(
            `INSERT INTO users (user_id, password, name)
             VALUES ($1, $2, $3)`,
            [userId, hashedPassword, name]
        );

        return res.redirect(
            "/login?message=" +
            encodeURIComponent("Account created! Please sign in.")
        );
    } catch (error) {
        if (error.code === "23505") {
            return res.status(409).render("signup", {
                error: "That user ID is already taken."
            });
        }

        next(error);
    }
});

// LOGIN PAGE
app.get("/login", (req, res) => {
    res.render("login", {
        error: "",
        message: req.query.message || ""
    });
});

// SIGN IN
app.post("/login", async (req, res, next) => {
    const userId = (req.body.user_id || "").trim();
    const password = req.body.password || "";

    try {
        const result = await pool.query(
            `SELECT user_id, password, name
             FROM users
             WHERE user_id = $1`,
            [userId]
        );

        const account = result.rows[0];

        if (
            !account ||
            !account.password.startsWith("$2") ||
            !(await bcrypt.compare(password, account.password))
        ) {
            return res.status(401).render("login", {
                error: "Invalid user ID or password.",
                message: ""
            });
        }

        // Regenerate the session after authentication.
        req.session.regenerate((err) => {
            if (err) return next(err);

            req.session.user = {
                user_id: account.user_id,
                name: account.name
            };

            req.session.save((saveError) => {
                if (saveError) return next(saveError);
                res.redirect("/");
            });
        });
    } catch (error) {
        next(error);
    }
});

// LOG OUT
app.post("/logout", requireLogin, (req, res, next) => {
    req.session.destroy((error) => {
        if (error) return next(error);

        res.clearCookie("connect.sid");
        res.redirect("/");
    });
});

// CREATE A POST
app.post("/posts", requireLogin, async (req, res, next) => {
    const title = (req.body.title || "").trim();
    const body = (req.body.content || "").trim();

    if (!title || !body) {
        return res.redirect(
            "/?message=" +
            encodeURIComponent("Please provide a title and post content.")
        );
    }

    if (title.length > 255) {
        return res.redirect(
            "/?message=" +
            encodeURIComponent("The title must be 255 characters or fewer.")
        );
    }

    try {
        await pool.query(
            `INSERT INTO blogs
                (creator_name, creator_user_id, title, body)
             VALUES ($1, $2, $3, $4)`,
            [
                req.session.user.name,
                req.session.user.user_id,
                title,
                body
            ]
        );

        res.redirect("/");
    } catch (error) {
        next(error);
    }
});

// EDIT PAGE: only the post's creator can edit it.
app.get("/posts/edit/:id", requireLogin, async (req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT * FROM blogs
             WHERE blog_id = $1 AND creator_user_id = $2`,
            [req.params.id, req.session.user.user_id]
        );

        if (result.rows.length === 0) {
            return res.status(404).send(
                "Post not found, or you do not have permission to edit it."
            );
        }

        res.render("edit", {
            post: result.rows[0],
            user: req.session.user
        });
    } catch (error) {
        next(error);
    }
});

// UPDATE POST: ownership is checked in the SQL statement.
app.post("/posts/edit/:id", requireLogin, async (req, res, next) => {
    const title = (req.body.title || "").trim();
    const body = (req.body.content || "").trim();

    if (!title || !body || title.length > 255) {
        return res.redirect(
            "/?message=" +
            encodeURIComponent("Please enter a valid title and post body.")
        );
    }

    try {
        const result = await pool.query(
            `UPDATE blogs
             SET title = $1, body = $2
             WHERE blog_id = $3 AND creator_user_id = $4
             RETURNING blog_id`,
            [title, body, req.params.id, req.session.user.user_id]
        );

        if (result.rowCount === 0) {
            return res.status(404).send(
                "Post not found, or you do not have permission to edit it."
            );
        }

        res.redirect("/");
    } catch (error) {
        next(error);
    }
});

// DELETE POST: only the creator can delete it.
app.post("/posts/delete/:id", requireLogin, async (req, res, next) => {
    try {
        const result = await pool.query(
            `DELETE FROM blogs
             WHERE blog_id = $1 AND creator_user_id = $2
             RETURNING blog_id`,
            [req.params.id, req.session.user.user_id]
        );

        if (result.rowCount === 0) {
            return res.status(404).send(
                "Post not found, or you do not have permission to delete it."
            );
        }

        res.redirect("/");
    } catch (error) {
        next(error);
    }
});

// Display unexpected errors without exposing database details.
app.use((err, req, res, next) => {
    console.error("Application error:", err.message);

    if (res.headersSent) return next(err);

    res.status(500).send(
        "Something went wrong. Check the terminal for the error."
    );
});

app.listen(PORT, () => {
    console.log(`Blog app running at http://localhost:${PORT}`);
});
