const express = require('express');
const router = express.Router();
const helper = require(__class_dir + '/helper.class.js');
const m$task = require(__module_dir + '/task.module.js');
const jwt = require('jsonwebtoken');
const config = require(`${__config_dir}/app.config.json`);


router.post('/', async function (req, res, next) {
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

        const addTask = await m$task.add(user.id, req.body)
        helper.sendResponse(res, addTask);
    });
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

        const updateTask = await m$task.update(user.id, req.body)
        helper.sendResponse(res, updateTask);
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

        const deleteTask = await m$task.delete(user.id, req.body)
        helper.sendResponse(res, deleteTask);
    });
})

router.get('/', async function (req, res, next) {
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

        const getTask = await m$task.get(user.id)
        helper.sendResponse(res, getTask);
    });
})

module.exports = router;
