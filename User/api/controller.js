const {
    create,
    getUserBySdt,
    getUserById,
    updateUser,
    checkSdt,
    updatePassword
} = require("./service.js");

const { hashSync, genSaltSync, compareSync } = require("bcrypt");
const { sign } = require("jsonwebtoken");

module.exports = {
    createUser: (req, res) => {
        const body = req.body;
        const sdt = req.body.SoDienThoai;
        const salt = genSaltSync(10);
        body.Password = hashSync(body.Password, salt);
        checkSdt(sdt, (err, results) => {
            if (err) {
                console.log(err);
            }
            else {
                if (results.recordset.length > 0) {
                    return res.status(500).json({
                        success: 0,
                        message: 'Số điện thoại đã tồn tại',
                    });
                } else {
                    create(body, (err, results) => {
                        if (err) {
                            return res.status(500).json({
                                success: 0,
                                message: "Lỗi kết nối cơ sở dữ liệu"
                            });
                        }
                        let token = sign({ result: results }, "imposter", { expiresIn: "7d" });
                        return res.status(200).json({
                            success: 1,
                            message: 'Đăng kí tài khoản thành công!',
                            token: token
                        });
                    });
                }
            }
        });
    },

    checkSdt: (req, res) => {
        const sdt = req.body.SoDienThoai;
        checkSdt(sdt, (err, results) => {
            if (err) {
                console.log(err);
            }
            else {
                if (results.recordset.length > 0) {
                    return res.status(500).json({
                        success: 0,
                        message: 'Số điện thoại đã tồn tại',
                    });
                } else {
                    return res.status(200).json({
                        success: 1,
                        message: 'Số điện thoại hợp lệ',
                    });
                }
            }
        });
    },

    login: (req, res) => {
        const body = req.body;
        getUserBySdt(body.SoDienThoai, (err, results) => {
            if (err) {
                console.log(err);
            }
            if (!results) {
                return res.json({
                    success: 0,
                    message: "Số điện thoại hoặc mật khẩu không hợp lệ"
                });
            }
            else {
                if (results.Status == 0) {
                    return res.json({
                        success: 2,
                        message: "Tài khoản của bạn đã bị khoá"
                    });
                }

                const result = compareSync(body.Password, results.Password);    //Kiểm tra pass
                if (result) {
                    results.Password = undefined;
                    let token = sign({ result: results }, "imposter", { expiresIn: "7d" });
                    return res.status(201).json({
                        success: 1,
                        message: "Đăng nhập thành công",
                        token: token
                    });
                } else {
                    return res.json({
                        success: 0,
                        message: "Số điện thoại hoặc mật khẩu không hợp lệ"
                    });
                }
            }

        });
    },

    getUserBySdt: (req, res) => {
        const sdt = req.params.sdt;
        getUserBySdt(sdt, (err, results) => {
            if (err) {
                console.log(err);
                return;
            }
            if (!results) {
                return res.json({
                    success: 0,
                    message: "Không tìm thấy"
                });
            } else {
                if (results.Status == 0) {
                    return res.json({
                        success: 2,
                        message: "Tài khoản của bạn đã bị khoá"
                    });
                }
                results.password = undefined;
                return res.json({
                    success: 1,
                    data: results
                });
            }
        });
    },

    getUserById: (req, res) => {
        const id = req.params.id;
        getUserById(id, (err, results) => {
            if (err) {
                console.log(err);
                return;
            }
            if (!results) {
                return res.json({
                    success: 0,
                    message: "Không tìm thấy hoặc đã bị khoá"
                });
            }
            results.password = undefined;
            return res.json({
                success: 1,
                data: results
            });
        });
    },

    updateUsers: (req, res) => {
        const body = req.body;

        if (body.Password != null) {
            const salt = genSaltSync(10);
            body.Password = hashSync(body.Password, salt);
        }
        updateUser(body, (err, results) => {
            if (err) {
                console.log(err);
                return res.json({
                    success: 0,
                    message: "Có lỗi xảy ra"
                });
            }
            return res.json({
                success: 1,
                message: "Cập nhật thành công"
            });
        });
    },

    updatePassword: (req, res) => {
        const body = req.body;

        if (body.Password != null) {
            const salt = genSaltSync(10);
            body.Password = hashSync(body.Password, salt);
        }
        updatePassword(body, (err, results) => {
            if (err) {
                console.log(err);
                return res.json({
                    success: 0,
                    message: "Có lỗi xảy ra"
                });
            }

            if (results.rowsAffected[0] != 0) {
                return res.json({
                    success: 1,
                    message: "Cập nhật thành công"
                });
            } else {
                return res.json({
                    success: 0,
                    message: "Cập nhật không thành công"
                });
            }
        });
    },
};
