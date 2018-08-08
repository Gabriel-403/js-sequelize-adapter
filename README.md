Sequelize Adapter [![Build Status](https://travis-ci.org/casbin/sequelize-adapter.svg?branch=master)](https://travis-ci.org/casbin/sequelize-adapter) [![Coverage Status](https://coveralls.io/repos/github/casbin/sequelize-adapter/badge.svg?branch=master)](https://coveralls.io/github/casbin/sequelize-adapter?branch=master) [![Godoc](https://godoc.org/github.com/casbin/sequelize-adapter?status.svg)](https://godoc.org/github.com/casbin/sequelize-adapter)
====

Sequelize Adapter is the [Sequelize](https://github.com/sequelize/sequelize) adapter for [Casbin](https://github.com/casbin/node-casbin). With this library, Casbin can load policy from Sequelize supported database or save policy to it.

Based on [Officially Supported Databases](http://docs.sequelizejs.com), The current supported databases are:

- MySQL
- PostgreSQL
- Sqlite3
- Mssql

You may find other 3rd-party supported DBs in Sequelize website or other places.

## Installation

    npm install sequelize-adapter

## Simple Example

```javascript
const Adapter = require('sequelize-adapter')
const { Enforcer } = require('casbin')

module.exports = () => {
	// Initialize a Sequelize adapter and use it in a Casbin enforcer:
	// The adapter will use the MySQL database named "casbin".
	// If it doesn't exist, the adapter will create it automatically.
	const adapter = new Adapter('database', 'username', 'password', {host: 'localhost', dialect: 'mysql'}) // Your driver and data source. 
	const enforcer = new Enforcer('examples/rbac_model.conf', adapter)
	
	// Or you can use an existing DB "abc" like this:
    // The adapter will use the table named "casbin_rule".
    // If it doesn't exist, the adapter will create it automatically.
    // adapter = sequelizeadapter.newAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/abc", true)

	// Load the policy from DB.
	enforcer.loadPolicy()
	
	// Check the permission.
	enforcer.enforce('alice', 'data1', 'read')
	
	// Modify the policy.
	// e.addPolicy(...)
	// e.removePolicy(...)
	
	// Save the policy back to DB.
	enforcer.savePolicy()
}
```

## Getting Help

- [Casbin](https://github.com/casbin/node-casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
