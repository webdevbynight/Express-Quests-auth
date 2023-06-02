require('dotenv').config();
const argon2 = require('argon2'),
    jwt = require('jsonwebtoken'),
    hashPassword = async (req, res, next) =>
    {
        try
        {
            const password = req.body.password ? req.body.password : req.body.hashedPassword,
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
    },
    verifyPassword = async (req, res) =>
    {
        try
        {
            const verifiedPassword = await argon2.verify(req.user.hashedPassword, req.body.password);
            if (verifiedPassword)
            {
                const payload =
                    {
                        sub: req.user.id
                    },
                    options =
                    {
                        expiresIn: '1h'
                    },
                    token = jwt.sign(payload, process.env.JWT_SECRET, options);
                delete req.user.hashedPassword;
                res.status(200).send({ token, user: req.user });
            }
            else res.sendStatus(401);
        }
        catch (err)
        {
            console.error(err);
            res.status(500).send('There was a problem when verifying the password.')
        }
    },
    verifyToken = (req, res, next) =>
    {
        try
        {
            const authorizationHeader = req.get('Authorization');
            if (!authorizationHeader) throw new Error('Authorization header is missing.');
            const [type, token] = authorizationHeader.split(' ');
            if (type !== 'Bearer') throw new Error('Authorization header has not the `Bearer` type.');
            req.payload = jwt.verify(token, process.env.JWT_SECRET);
            next();
        }
        catch (err)
        {
            console.error(err);
            res.sendStatus(401);
        }
    };

module.exports =
{
    hashPassword,
    verifyPassword,
    verifyToken
};