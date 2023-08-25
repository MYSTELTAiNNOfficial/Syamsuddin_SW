const express = require('express');
const router = express.Router();
const helper = require(__class_dir + '/helper.class.js');
const m$auth = require(__module_dir + '/login.module.js');
const jwt = require('jsonwebtoken');
const config = require(`${__config_dir}/app.config.json`);

router.post('/register', async function (req, res, next) {
    const regist = await m$auth.register(req.body)
    helper.sendResponse(res, regist);
})

router.post('/login', async function (req, res, next) {
    const login = await m$auth.auth(req.body)
    helper.sendResponse(res, login);
})

router.put('/', async function (req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return helper.sendResponse(res, {
            status: false,
            code: 401,
            error: 'Unauthorized'
        });
    }

    const token = authHeader.split(' ');
    if (token[0] !== "Bearer") {
        return helper.sendResponse(res, {
            status: false,
            code: 401,
            error: 'Unauthorized'
        });
    }
    if (!token[1]) {
        return helper.sendResponse(res, {
            status: false,
            code: 401,
            error: 'Unauthorized'
        });
    }

    jwt.verify(token[1], config.jwt.secret, async (err, user) => {
        if (err) {
            return helper.sendResponse(res, {
                status: false,
                code: 403,
                error: 'Forbidden'
            });
        }

        const update = await m$auth.update(user.id, req.body)
        helper.sendResponse(res, update);
    });
})

router.delete('/', async function (req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return helper.sendResponse(res, {
            status: false,
            code: 401,
            error: 'Unauthorized'
        });
    }

    const token = authHeader.split(' ');
    if (token[0] !== "Bearer") {
        return helper.sendResponse(res, {
            status: false,
            code: 401,
            error: 'Unauthorized'
        });
    }
    if (!token[1]) {
        return helper.sendResponse(res, {
            status: false,
            code: 401,
            error: 'Unauthorized'
        });
    }

    jwt.verify(token[1], config.jwt.secret, async (err, user) => {
        if (err) {
            return helper.sendResponse(res, {
                status: false,
                code: 403,
                error: 'Forbidden'
            });
        }

        const del = await m$auth.delete(user.id)
        helper.sendResponse(res, del);
    });
})

module.exports = router;