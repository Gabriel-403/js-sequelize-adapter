// Copyright 2018 The Casbin Authors. All Rights Reserved.
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

const Adapter = require('../lib/adapter')
const enforcer = require('casbin')

function testGetPolicy (e, res) {
}

test('TestAdapter', async () => {
  // Because the DB is empty at first,
  // so we need to load the policy from the file adapter (.CSV) first.
  let e = await enforcer.Enforcer.newEnforcer('examples/rbac_model.conf', 'examples/rbac_policy.csv')

  let a = await new Adapter('casbin', 'root', '', {host: 'localhost', port: 3306, dialect: 'mysql'})
  // This is a trick to save the current policy to the DB.
  // We can't call e.savePolicy() because the adapter in the enforcer is still the file adapter.
  // The current policy means the policy in the Node-Casbin enforcer (aka in memory).
  a.savePolicy(e.getModel())

  // Clear the current policy.
  e.clearPolicy()
  testGetPolicy(e, '')

  // Load the policy from DB.
  a.loadPolicy(e.getModel())
  testGetPolicy(e, [
    ['alice', 'data1', 'read'],
    ['bob', 'data2', 'write'],
    ['data2_admin', 'data2', 'read'],
    ['data2_admin', 'data2', 'write']])

  // Note: you don't need to look at the above code
  // if you already have a working DB with policy inside.

  // Now the DB has policy, so we can provide a normal use case.
  // Create an adapter and an enforcer.
  // newEnforcer() will load the policy automatically.
  a = await new Adapter('casbin', 'root', '', {host: 'localhost', port: 3306, dialect: 'mysql'})
  e = await enforcer.Enforcer.newEnforcer('examples/rbac_model.conf', a)
  testGetPolicy(e, [
    ['alice', 'data1', 'read'],
    ['bob', 'data2', 'write'],
    ['data2_admin', 'data2', 'read'],
    ['data2_admin', 'data2', 'write']])
})
