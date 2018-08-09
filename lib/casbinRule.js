module.exports = function Model (sequelize, DataTypes) {
  const CasbinRule = sequelize.define('casbin_rule', {
    id: {
      type: DataTypes.UUID,
      allowNull: false,
      unique: true,
      primaryKey: true,
      defaultValue: DataTypes.UUIDV4
    },
    p_type: {
      type: DataTypes.STRING(100),
      allowNull: false
    },
    v0: {
      type: DataTypes.STRING(100),
      allowNull: true
    },
    v1: {
      type: DataTypes.STRING(100),
      allowNull: true
    },
    v2: {
      type: DataTypes.STRING(100),
      allowNull: true
    },
    v3: {
      type: DataTypes.STRING(100),
      allowNull: true
    },
    v4: {
      type: DataTypes.STRING(100),
      allowNull: true
    },
    v5: {
      type: DataTypes.STRING(100),
      allowNull: true
    }
  }, {
    timestamps: false,
    underscored: true,
    tableName: 'casbin_rule'
  })
  return CasbinRule
}
