// Copyright 2020 Self Group Ltd. All Rights Reserved.

var test = require('tape')
var crypto = require('../')

test('account creation test', function (t) {
  t.plan(3)

  t.ok(crypto.create_olm_account(), 'create olm account')
  t.ok(crypto.create_olm_account_derrived_keys('uUG4E51Hv5k4QH5lgF+5CG44SsxGz/PlM1phmLc2eqE'), 'create olm account with derrived curve25519 key')

  t.throws(function () {
    crypto.create_olm_account_derrived_keys('bad key')
  }, /Could not decode seed/, 'create olm account with bad seed')
})

test('account identity keys test', function (t) {
  t.plan(2)

  var account = crypto.create_olm_account_derrived_keys('uUG4E51Hv5k4QH5lgF+5CG44SsxGz/PlM1phmLc2eqE')
  var identityKeys = JSON.parse(crypto.identity_keys(account))

  t.equal(identityKeys['ed25519'], 'RtSC8ETmFnU3FvXLha+zX6BugzS6Tzs0LuJEEgC7XBw')
  t.equal(identityKeys['curve25519'], '7W1agmEIeur7/ie2xYySADEVnFSvZdLskHPraYH461U')
})

test('account one time keys test', function (t) {
  t.plan(1)

  var account = crypto.create_olm_account_derrived_keys('uUG4E51Hv5k4QH5lgF+5CG44SsxGz/PlM1phmLc2eqE')
  crypto.create_account_one_time_keys(account, 100)
  var oneTimeKeys = JSON.parse(crypto.one_time_keys(account))

  t.equal(Object.keys(oneTimeKeys['curve25519']).length, 100)
})

test('account pickle unpickle test', function (t) {
  t.plan(4)

  var account = crypto.create_olm_account_derrived_keys('uUG4E51Hv5k4QH5lgF+5CG44SsxGz/PlM1phmLc2eqE')
  crypto.create_account_one_time_keys(account, 100)

  var pickle = crypto.pickle_account(account)

  t.equal(pickle.length, 9462)

  account = crypto.unpickle_account(pickle)

  var identityKeys = JSON.parse(crypto.identity_keys(account))
  var oneTimeKeys = JSON.parse(crypto.one_time_keys(account))

  t.equal(identityKeys['ed25519'], 'RtSC8ETmFnU3FvXLha+zX6BugzS6Tzs0LuJEEgC7XBw')
  t.equal(identityKeys['curve25519'], '7W1agmEIeur7/ie2xYySADEVnFSvZdLskHPraYH461U')
  t.equal(Object.keys(oneTimeKeys['curve25519']).length, 100)
})
