const services = require('../api/service')

module.exports = {
    uploadProductsImages(req, res) {
        console.log(req)
        services.uploadS3(req, res, (error) => {
            if (error) {
                res.status(500).json({
                    status: 'fail',
                    error: error
                });
            } else {
                if (req.files === undefined) {
                    res.status(500).json({
                        status: 'fail',
                        message: 'Error: No File Selected'
                    });
                } else {
                    let fileArray = req.files, fileLocation;
                    const images = [];
                    for (let i = 0; i < fileArray.length; i++) {
                        fileLocation = fileArray[i].location;
                        images.push(fileLocation)
                    }
                    return res.status(200).json({
                        status: 'ok',
                        locationArray: images
                    });

                }
            }
        })
    },

    addNameRoom(req, res, next) {
        const room = req.body;
        services.putNameRoom(room).then(data => {
            if (data)
                res.json({ success: 1, message: "Thêm room thành công" });
        }).catch(err => {
            next(err);
        });
    },

    deleteNameRoom(req, res, next) {
        const room = req.body;
        (services.findIDRoomByIdUser12(room.id_user_1, room.id_user_2).then(data => {
            if (data) {
                return services.deleteRoomByID(data.id_room);
            }
        }),
            services.findIDRoomByIdUser21(room.id_user_2, room.id_user_1).then(data => {
                if (data) {
                    return services.deleteRoomByID(data.id_room);
                }
            })
        ).then(data => {
            res.json({ success: 1, message: "Xóa room thành công" });
        }).catch(err => {
            next(err);
        });
    },

    findIDRoomByIdUser(req, res, next) {
        const room = req.body;
        services.findIDRoomByIdUser12(room.id_user_1, room.id_user_2).then(data => {
            if (data) {
                res.json({ success: 1, message: "Tồn tại mã room", id_room: data.id_room })
            }
            else {
                services.findIDRoomByIdUser21(room.id_user_2, room.id_user_1).then(data => {
                    if (data) {
                        res.json({
                            success: 1, message: "Tồn tại mã room", id_room: data.id_room
                        })
                    }
                    else
                        res.json({ success: 0, message: "Không tồn tại room" })
                })
            }
        })
    },

    createTable(req, res, next) {
        const tableName = req.body.id_room

        services.createTable(tableName).then(data => {
            res.json({ success: 1, message: "Tạo table dynamo thành công" })
        }).catch(err => {
            res.json({ success: 0, message: "Đã tồn table dynamo" })
        })
    },

    scanItemMessage(req, res, next) {
        const tableName = req.body.id_room
        const itemLast = req.body.itemLast
        services.scanItemMessage(tableName, itemLast).then(data => {
            res.json(data)
        })
    },

    scanFirstItemMessage(req, res, next) {
        const tableName = req.body.id_room
        services.scanFirstItemMessage(tableName).then(data => {
            res.json(data)
        })
    },

    getAllRoomFor_A_User(req, res) {
        const id_user_1 = req.params.id

        services.getAllRoomFor_A_User(id_user_1).then(data => {
            res.json(data)
        })
    }
}