const argon2 = require('argon2'),
    hashPassword = async (req, res, next) =>
    {
        try
        {
            const password = req.body.password,
                hashingOptions =
                {
                    memoryCost: 2 ** 14,
                    timeCost: 2,
                    parallelism: 1
                },
                hashedPassword = await argon2.hash(password, hashingOptions);
            req.body.hashedPassword = hashedPassword;
            delete password;
            next();
        }
        catch (err)
        {
            console.error(err);
            res.status(500).send('There was a problem when validating the password.');
        }
    };

    module.exports =
    {
        hashPassword
    };