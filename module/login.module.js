const config = require(`${__config_dir}/app.config.json`);
const { debug } = config;
const mysql = new (require(`${__class_dir}/mariadb.class.js`))(config.db);
const Joi = require('joi');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

class _login {
    async auth(data) {
        const schema = Joi.object({
            username: Joi.string().required(),
            password: Joi.string().required()
        }).options({
            abortEarly: false
        })

        const validation = schema.validate(data)
        if (validation.error) {
            const errorDetails = validation.error.details.map((detail) => {
                detail.message
            })

            return {
                status: false,
                code: 422,
                error: errorDetails.join(', ')
            }
        }

        const sql = {
            query: `SELECT * FROM users WHERE username = ?`,
            params: [data.username]
        }

        return mysql.query(sql.query, sql.params)
            .then(async (datadb) => {
                if (datadb.length == 0) {
                    return {
                        status: false,
                        code: 404,
                        error: 'User not found'
                    }
                }

                const user = datadb[0]
                const compare = await bcrypt.compare(data.password, user.password)
                if (!compare) {
                    return {
                        status: false,
                        code: 401,
                        error: 'Wrong password'
                    }
                }

                const token = jwt.sign({
                    id: user.id,
                    username: user.username
                }, config.jwt.secret)

                return {
                    status: true,
                    data: {
                        token
                    }
                }
            })
    }

    async register(data) {
        // Validate data
        const schema = Joi.object({
            username: Joi.string().required(),
            password: Joi.string().required()
        }).options({
            abortEarly: false
        })
        const validation = schema.validate(data)
        console.log(validation)
        if (validation.error) {
            const errorDetails = validation.error.details.map((detail) => {
                detail.message
            })

            return {
                status: false,
                code: 422,
                error: errorDetails.join(', ')
            }
        }

        const salt = await bcrypt.genSalt(10)
        const hash = await bcrypt.hash(data.password, salt)
        data.password = hash

        // Insert data to database
        const sql = {
            query: `INSERT INTO users (username, password) VALUES (?, ?)`,
            params: [data.username, data.password]
        }

        return mysql.query(sql.query, sql.params)
            .then(data => {
                return {
                    status: true,
                    data
                }
            })
            .catch(error => {
                if (debug) {
                    console.error('register login Error: ', error)
                }

                return {
                    status: false,
                    error
                }
            })
    }

    async update(data) {
        // Validate data
        const schema = Joi.object({
            id: Joi.number().required(),
            username: Joi.string().required(),
            password: Joi.string().required()
        }).options({
            abortEarly: false
        })
        const validation = schema.validate(data)
        if (validation.error) {
            const errorDetails = validation.error.details.map((detail) => {
                detail.message
            })

            return {
                status: false,
                code: 422,
                error: errorDetails.join(', ')
            }
        }

        const salt = await bcrypt.genSalt(10)
        const hash = await bcrypt.hash(data.password, salt)
        data.password = hash

        // Insert data to database
        const sql = {
            query: `UPDATE users SET username = ?, password = ? WHERE id = ?`,
            params: [data.username, data.password, data.id]
        }

        return mysql.query(sql.query, sql.params)
            .then(data => {
                return {
                    status: true,
                    data
                }
            })
            .catch(error => {
                if (debug) {
                    console.error('update login Error: ', error)
                }

                return {
                    status: false,
                    error
                }
            })
    }

    async delete(data) {
        // Validate data
        const schema = Joi.object({
            id: Joi.number().required()
        }).options({
            abortEarly: false
        })
        const validation = schema.validate(data)
        if (validation.error) {
            const errorDetails = validation.error.details.map((detail) => {
                detail.message
            })

            return {
                status: false,
                code: 422,
                error: errorDetails.join(', ')
            }
        }

        // Insert data to database
        const sql = {
            query: `DELETE FROM users WHERE id = ?`,
            params: [data.id]
        }

        return mysql.query(sql.query, sql.params)
            .then(data => {
                return {
                    status: true,
                    data
                }
            })
            .catch(error => {
                if (debug) {
                    console.error('delete login Error: ', error)
                }

                return {
                    status: false,
                    error
                }
            })
    }
}

module.exports = new _login();