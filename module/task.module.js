const config = require(`${__config_dir}/app.config.json`);
const { debug } = config;
const mysql = new (require(`${__class_dir}/mariadb.class.js`))(config.db);
const Joi = require('joi');

class _task {
    // add(data) {

    //     // Validate data
    //     const schema = Joi.object({
    //         item: Joi.string()
    //     }).options({
    //         abortEarly: false
    //     })
    //     const validation = schema.validate(data)
    //     if (validation.error) {
    //         const errorDetails = validation.error.details.map((detail) => {
    //             detail.message
    //         })

    //         return {
    //             status: false,
    //             code: 422,
    //             error: errorDetails.join(', ')
    //         }
    //     }

    //     // Insert data to database
    //     const sql = {
    //         query: `INSERT INTO task (items) VALUES (?)`,
    //         params: [data.item]
    //     }

    //     return mysql.query(sql.query, sql.params)
    //         .then(data => {
    //             return {
    //                 status: true,
    //                 data
    //             }
    //         })
    //         .catch(error => {
    //             if (debug) {
    //                 console.error('add task Error: ', error)
    //             }

    //             return {
    //                 status: false,
    //                 error
    //             }
    //         })
    // }
    // update(data) {
    //     // Validate data
    //     const schema = Joi.object({
    //         id: Joi.number().required(),
    //         item: Joi.string()
    //     }).options({
    //         abortEarly: false
    //     })
    //     const validation = schema.validate(data)
    //     if (validation.error) {
    //         const errorDetails = validation.error.details.map((detail) => {
    //             detail.message
    //         })

    //         return {
    //             status: false,
    //             code: 422,
    //             error: errorDetails.join(', ')
    //         }
    //     }

    //     // Update data to database
    //     const sql = {
    //         query: `UPDATE task SET items = ? WHERE id = ?`,
    //         params: [data.item, data.id]
    //     }

    //     return mysql.query(sql.query, sql.params)
    //         .then(data => {
    //             return {
    //                 status: true,
    //                 data
    //             }
    //         })
    //         .catch(error => {
    //             if (debug) {
    //                 console.error('update task Error: ', error)
    //             }

    //             return {
    //                 status: false,
    //                 error
    //             }
    //         })
    // }
    // delete(data) {
    //     // Validate data
    //     const schema = Joi.object({
    //         id: Joi.number().required()
    //     }).options({
    //         abortEarly: false
    //     })
    //     const validation = schema.validate(data)
    //     if (validation.error) {
    //         const errorDetails = validation.error.details.map((detail) => {
    //             detail.message
    //         })

    //         return {
    //             status: false,
    //             code: 422,
    //             error: errorDetails.join(', ')
    //         }
    //     }

    //     // Delete data to database
    //     const sql = {
    //         query: `DELETE FROM task WHERE id = ?`,
    //         params: [data.id]
    //     }

    //     return mysql.query(sql.query, sql.params)
    //         .then(data => {
    //             return {
    //                 status: true,
    //                 data
    //             }
    //         })
    //         .catch(error => {
    //             if (debug) {
    //                 console.error('delete task Error: ', error)
    //             }

    //             return {
    //                 status: false,
    //                 error
    //             }
    //         })
    // }
    // get(data) {
    //     // Validate data
    //     const schema = Joi.object({
    //         id: Joi.number()
    //     }).options({
    //         abortEarly: false
    //     })
    //     const validation = schema.validate(data)
    //     if (validation.error) {
    //         const errorDetails = validation.error.details.map((detail) => {
    //             detail.message
    //         })

    //         return {
    //             status: false,
    //             code: 422,
    //             error: errorDetails.join(', ')
    //         }
    //     }

    //     // Get data to database
    //     const sql = {
    //         query: `SELECT * FROM task WHERE id = ?`,
    //         params: [data.id]
    //     }

    //     return mysql.query(sql.query, sql.params)
    //         .then(data => {
    //             return {
    //                 status: true,
    //                 data
    //             }
    //         })
    //         .catch(error => {
    //             if (debug) {
    //                 console.error('get task Error: ', error)
    //             }

    //             return {
    //                 status: false,
    //                 error
    //             }
    //         })
    // }

    add(id, data) {
        // Validate data
        const schema = Joi.object({
            todo: Joi.string(),
            description: Joi.string(),
        }).options({
            abortEarly: false
        })
        console.log(data)
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
            query: `INSERT INTO todos (id, id_user, todo, description, is_complete) VALUES (NULL, ?, ?, ?, 'false')`,
            params: [id, data.todo, data.description]
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
                    console.error('add task Error: ', error)
                }

                return {
                    status: false,
                    error
                }
            })
    }
    update(id, data) {
        // Validate data
        const schema = Joi.object({
            id: Joi.number().required(),
            todo: Joi.string(),
            description: Joi.string(),
            is_complete: Joi.string()
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

        // Update data to database
        const sql = {
            query: `UPDATE todos SET todo = ?, description = ?, is_complete = ? WHERE id = ? AND id_user = ?`,
            params: [data.todo, data.description, data.is_complete, data.id, id]
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
                    console.error('update task Error: ', error)
                }

                return {
                    status: false,
                    error
                }
            })
    }
    delete(id, data) {
        // Validate data
        const schema = Joi.object({
            id: Joi.number().required()
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

        // Delete data to database
        const sql = {
            query: `DELETE FROM todos WHERE id = ? AND id_user = ?`,
            params: [data.id, id]
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
                    console.error('delete task Error: ', error)
                }

                return {
                    status: false,
                    error
                }
            })
    }
    get(id) {
        // Get data to database
        const sql = {
            query: `SELECT * FROM todos WHERE id_user = ?`,
            params: [id]
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
                    console.error('get task Error: ', error)
                }

                return {
                    status: false,
                    error
                }
            })
    }
}

module.exports = new _task();
