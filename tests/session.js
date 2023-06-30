// Copyright 2020 Self Group Ltd. All Rights Reserved.

var test = require('tape')
var crypto = require('../')

test('session create outbound test', function (t) {
  t.plan(1)

  var aliceAccount = crypto.create_olm_account()
  var bobAccount = crypto.create_olm_account()

  crypto.create_account_one_time_keys(bobAccount, 100)

  var bobsIdentityKey = JSON.parse(crypto.identity_keys(bobAccount))['curve25519']
  var bobsOneTimeKey = JSON.parse(crypto.one_time_keys(bobAccount))['curve25519']['AAAAAQ']

  var sessionWithBob = crypto.create_outbound_session(aliceAccount, bobsIdentityKey, bobsOneTimeKey)
  t.ok(sessionWithBob)
})
