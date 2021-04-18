module.exports = {
  filterObject: (obj, objArray, include, cb) => {
    try {
      let ret = include ? {} : Object.assign({}, obj);
      for (let i = 0; i < objArray.length; i++) {
        const key = objArray[i];
        if (obj[key] != undefined) {
          if (include) {
            ret[key] = obj[key];
          } else {
            delete ret[key];
          }
        }
      }
      if (cb) {
        return cb(ret);
      } else {
        return Promise.resolve(ret);
      }
    } catch (err) {
      console.log(err);
      return Promise.reject({
        message: err.message || "error at filterObject",
      });
    }
  },
  toObjectId: (id) => {
    try {
      return pie.packages.mongoose.Types.ObjectId(id);
    } catch (err) {
      console.log("Invalid object id passed", err);
    }
    return null;
  },
  model: (m) => (m ? pie.db.models[m] : pie.db.models),

  paginationDefault: () => {
    return { _id: null, result: [], totalResultSize: 0, totalPages: 0 };
  },
  pagination: (pageNo, pageSize) => {
    return pageNo && pageNo > 0
      ? [
          {
            $group: {
              _id: null,
              result: { $push: "$$ROOT" },
            },
          },
          {
            $addFields: {
              totalResultSize: { $size: "$result" },
            },
          },
          {
            $addFields: {
              totalPages: {
                $ceil: { $divide: ["$totalResultSize", pageSize] },
              },
            },
          },
          {
            $addFields: {
              result: {
                $map: {
                  input: {
                    $range: [
                      (pageNo - 1) * pageSize,
                      {
                        $sum: [
                          (pageNo - 1) * pageSize,
                          {
                            $min: [
                              pageSize,
                              {
                                $subtract: [
                                  "$totalResultSize",
                                  pageSize * (pageNo - 1),
                                ],
                              },
                            ],
                          },
                        ],
                      },
                    ],
                  },
                  as: "i",
                  in: { $arrayElemAt: ["$result", "$$i"] },
                },
              },
            },
          },
        ]
      : [];
  },
};
