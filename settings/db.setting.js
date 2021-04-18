module.exports = {
  options: {
    url: pie.config.mongoUrl,
    useNewUrlParser: true,
    useUnifiedTopology: true,
    plugins: [
      [pie.packages.mongooseDelete, { overrideMethods: "all" }],
      (schema) => {
        schema.statics.aggregateSkipDelete = function (arr) {
          arr = arr || [];
          return this.aggregate([
            {
              $match: {
                deleted: false,
              },
            },
            ...arr,
          ]);
        };
        schema.statics.softDeleteById = function (id) {
          console.log(id);
          return this.findByIdAndUpdate(
            id,
            { $set: { deleted: true } },
            { new: true }
          );
        };
        schema.statics.softDeleteMany = function (filter) {
          return this.updateMany(
            filter,
            { $set: { deleted: true } },
            { new: true }
          );
        };
      },
    ],
  },
  onSuccess: (db) => {
    console.log("DB connected successfully");
  },
  onError: (err) => {
    console.log("DB connection failed", err);
  },
};
