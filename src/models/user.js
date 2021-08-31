const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
var findOrCreate = require("mongoose-findorcreate");

const shared_data = require("../shared-data/shared-vars");

const userSchema = new mongoose.Schema(
    {
        email: {
            type: String,
            unique: true,
            required: true,
            default: "fbuser", // TESTING
            trim: true,
            lowercase: true,
            validate(value) {
                if (!validator.isEmail(value)) {
                    throw new Error("Email is invalid!");
                }
            },
        },

        password: {
            type: String,
            trim: true,
            minlength: 6,
            required: true,
            default: "NOPASS",
        },

        fb_id: {
            type: Number,
            required: true,
            default: 0
        },

        tokens: [
            {
                token: {
                    type: String,
                    required: true,
                },
            },
        ],
    },

    {
        timestamps: true,
    }
);

// userSchema.virtual("invoices", {
//     ref: "Invoice",
//     localField: "_id",
//     foreignField: "customer",
// });

// GENERATE AUTH TOKEN USING JWT
userSchema.methods.generateAuthToken = async function () {
    const user = this;
    const token = jwt.sign({ _id: user._id.toString() }, process.env.JWT_SECRET);

    user.tokens = user.tokens.concat({ token });
    await user.save();

    return token;
};

userSchema.statics.findByCredentials = async (email, password) => {
    const user = await User.findOne({ email });

    if (!user) {
        shared_data.valid_user = false;
        return undefined;
        // throw new Error("Unable to login!");
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        shared_data.valid_user = false;
        return undefined;
        // throw new Error("Unable to login!");
    }

    shared_data.valid_user = true;
    return user;
};

// HASH PLAIN TEXT PASSWORDS
userSchema.pre("save", async function (next) {
    const user = this;

    if (user.isModified("password")) {
        user.password = await bcrypt.hash(user.password, 8);
    }

    next();
});

userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

module.exports = User;
