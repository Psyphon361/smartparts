require("../oauth/google");
const path = require("path");
const express = require("express");
const router = new express.Router();
const User = require("../models/user");
// const Invoice = require("../models/invoice");
const auth = require("../middleware/auth");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const shared_data = require("../shared-data/shared-vars");

router.get("/", async (req, res) => {
    res.status(200).send("Home"); // res.status(200).redirect("/");
});

router.get("/login", (req, res) => {
    res.status(200).send("Login page"); // res.status(200).redirect("/login");
});

router.post("/login", async (req, res) => {
    try {
        const user = await User.findByCredentials(
            req.body.email,
            req.body.password
        );

        if (shared_data.valid_user == false) {
            // res.redirect("/login");
            res.status(403).send("Redirecting to Login!");
        } else {
            const token = await user.generateAuthToken();

            res.cookie("jwt", token, {
                httpOnly: true,
                secure: false, // !!!!!------ MAKE IT secure: true BEFORE HOSTING --------!!!!!!
            });

            shared_data.user_is_authenticated = true; // FLAG FOR INDICATING WHETHER A USER IS LOGGED IN OR NOT

            res.status(200).send(
                "Login Success! Redirect to User Dashboard/Home"
            );
            // res.status(200).redirect("/");
        }
    } catch (e) {
        res.status(404).send("Not Found");
    }
});

router.get("/signup", (req, res) => {
    if (shared_data.user_is_authenticated) {
        res.status(403).redirect("/"); // REDIRECT BACK TO HOME IF ALREADY LOGGED IN
    } else {
        res.status(200).send("signup"); // RENDER SIGNUP PAGE
    }
});

router.post("/signup", async (req, res) => {
    shared_data.email_flag = false;

    // REGEX FOR STRONG PASSWORD

    // • 6+ characters
    // • One Upper & Lowercase
    // • One number
    // • Special characters (@$!%*?&)

    const re =
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/;

    if (!re.test(req.body.password)) {
        shared_data.strong_password = false;
        res.redirect("/signup");
    } else {
        const user = new User(req.body);

        const existing_user = await User.findOne({ email: user.email });

        if (existing_user) {
            shared_data.email_flag = true;
            res.redirect("/signup");
        } else {
            try {
                await user.save();
                const token = await user.generateAuthToken();

                res.cookie("jwt", token, {
                    // CREATING SESSION IN THE BROWSER
                    httpOnly: true,
                    secure: false, // !!!!!------ MAKE IT secure: true BEFORE HOSTING --------!!!!!!
                });

                shared_data.user_is_authenticated = true;

                res.status(201).send("User signed Up!");
            } catch (e) {
                res.status(400).send("Not Found");
            }
        }
    }
});

// GOOGLE OAUTH

router.get(
    "/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get(
    "/google/callback",
    passport.authenticate("google", { failureRedirect: "/signup" }),
    async function (req, res) {
        const user = req.user;
        const token = await user.generateAuthToken();

        res.cookie("jwt", token, {
            httpOnly: true,
            secure: false, // !!!!---- CHANGE IT TO secure: true IN PRODUCTION ----!!!!
        });

        shared_data.user_is_authenticated = true;

        res.status(201).send("User signed Up!");
    }
);

// FACEBOOK OAUTH

router.get("/facebook", passport.authenticate("facebook", { scope: "email" }));

router.get(
    "/facebook/callback",
    passport.authenticate("facebook", { failureRedirect: "/signup" }),

    async function (req, res) {
        const user = req.user;
        const token = await user.generateAuthToken();

        res.cookie("jwt", token, {
            httpOnly: true,
            secure: false, // !!!!!------ MAKE IT secure: true BEFORE HOSTING --------!!!!!!
        });

        shared_data.user_is_authenticated = true;

        res.status(201).send("User signed Up!");
    }
);

router.get("/logout", auth, async (req, res) => {
    try {
        req.user.tokens = req.user.tokens.filter((token) => {
            return token.token !== req.token;
        });

        await req.user.save();

        res.status(200).send("Successfully Logged out!");

        // res.redirect("/");
    } catch (e) {
        res.status(500).send();
    }
});

module.exports = router;
