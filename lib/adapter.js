// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const { Helper } = require('casbin')
const Sequelize = require('sequelize')
const Model = require('./casbinRule')

module.exports = class Adapter {
  // NewAdapter is the constructor for Adapter.
  // dbSpecified is an optional bool parameter. The default value is false.
  // It's up to whether you have specified an existing DB in dataSourceName.
  // If dbSpecified == true, you need to make sure the DB in dataSourceName exists.
  // If dbSpecified == false, the adapter will automatically create a DB named "casbin".
  constructor (database = 'test', username = 'root', password = '123456', { host, port, dialect }) {
    this.sequelize = new Sequelize(database, username, password, {
      host: host || 'localhost',
      port: port || 3306,
      dialect: dialect || 'mysql',
      pool: {
        max: 5,
        min: 0,
        idle: 10000
      },
      logging: false,
      benchmark: true
    })
    this.CasbinRule = Model(this.sequelize, Sequelize)
  }

  // init
  async init (model) {
    try {
      await this.authenticate()
      await this.sync()
    } catch (e) {
      throw e
    }
  }

  // authenticate is the destructor for Adapter.
  async authenticate () {
    await this.sequelize.authenticate()
  }

  // sync is the destructor for Adapter.
  async sync () {
    await this.CasbinRule.sync()
  }

  loadPolicyLine (line, model) {
    let lineText = line.p_type
    if (line.v0) {
      lineText += ', ' + line.v0
    }
    if (line.v1) {
      lineText += ', ' + line.v1
    }
    if (line.v2) {
      lineText += ', ' + line.v2
    }
    if (line.v3) {
      lineText += ', ' + line.v3
    }
    if (line.v4) {
      lineText += ', ' + line.v4
    }
    if (line.v5) {
      lineText += ', ' + line.v5
    }
    Helper.loadPolicyLine(lineText, model)
  }

  // loadPolicy loads policy from database.
  async loadPolicy (model) {
    const {CasbinRule} = this
    const lines = await CasbinRule.findAll({order: [['id', 'ASC']]})

    for (const line of lines) {
      this.loadPolicyLine(line.toJSON(), model)
    }
  }

  savePolicyLine (ptype, rule) {
    const line = {p_type: ptype}

    if (rule.length > 0) {
      line.v0 = rule[0]
    }
    if (rule.length > 1) {
      line.v1 = rule[1]
    }
    if (rule.length > 2) {
      line.v2 = rule[2]
    }
    if (rule.length > 3) {
      line.v3 = rule[3]
    }
    if (rule.length > 4) {
      line.v4 = rule[4]
    }
    if (rule.length > 5) {
      line.v5 = rule[5]
    }

    return line
  }

  // savePolicy saves policy to database.
  async savePolicy (model) {
    const {CasbinRule} = this
    let lines = []
    let astMap = model.model.get('p')
    for (const [ptype, ast] of astMap) {
      for (const rule of ast.policy) {
        const line = this.savePolicyLine(ptype, rule)
        lines.push(line)
      }
    }

    astMap = model.model.get('g')
    for (const [ptype, ast] of astMap) {
      for (const rule of ast.policy) {
        const line = this.savePolicyLine(ptype, rule)
        lines.push(line)
      }
    }

    await CasbinRule.bulkCreate(lines)
  }

  // addPolicy adds a policy rule to the storage.
  async addPolicy (sec, ptype, rules) {
    const {CasbinRule} = this
    const line = this.savePolicyLine(ptype, rules)
    await CasbinRule.create(line)
  }

  // removePolicy removes a policy rule from the storage.
  async removePolicy (sec, ptype, rules) {
    const {CasbinRule} = this
    const where = this.savePolicyLine(ptype, rules)
    await CasbinRule.destroy({where})
  }

  // removeFilteredPolicy removes policy rules that match the filter from the storage.
  async removeFilteredPolicy (sec, ptype, fieldIndex, ...fieldValues) {
    const {CasbinRule} = this
    const where = {p_type: ptype}
    const sum = fieldIndex + fieldValues.length
    let count = 0

    if (fieldIndex <= count && sum > count) {
      where.v0 = fieldValues[count - fieldIndex]
    }
    count += 1
    if (fieldIndex <= count && sum > count) {
      where.v1 = fieldValues[count - fieldIndex]
    }
    count += 1
    if (fieldIndex <= count && sum > count) {
      where.v2 = fieldValues[count - fieldIndex]
    }
    count += 1
    if (fieldIndex <= count && sum > count) {
      where.v3 = fieldValues[count - fieldIndex]
    }
    count += 1
    if (fieldIndex <= count && sum > count) {
      where.v4 = fieldValues[count - fieldIndex]
    }
    count += 1
    if (fieldIndex <= count && sum > count) {
      where.v5 = fieldValues[count - fieldIndex]
    }

    await CasbinRule.destroy({where})
  }
}
