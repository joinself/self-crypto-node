// Copyright 2020 Self Group Ltd. All Rights Reserved.

var test = require('tape')
var crypto = require('../')

test('session encrypt decrypt test', function (t) {
  t.plan(6)

  var aliceAccount = crypto.create_olm_account()
  var bobAccount = crypto.create_olm_account()

  crypto.create_account_one_time_keys(bobAccount, 100)

  var bobsIdentityKey = JSON.parse(crypto.identity_keys(bobAccount))['curve25519']
  var bobsOneTimeKey = JSON.parse(crypto.one_time_keys(bobAccount))['curve25519']['AAAAAQ']

  var sessionWithBob = crypto.create_outbound_session(aliceAccount, bobsIdentityKey, bobsOneTimeKey)
  t.ok(sessionWithBob)

  var ciphertextForBob = crypto.encrypt(sessionWithBob, 'hello bob')

  var sessionWithAlice = crypto.create_inbound_session(bobAccount, ciphertextForBob)
  t.ok(sessionWithAlice)

  var plaintextForBob = crypto.decrypt(sessionWithAlice, ciphertextForBob, 0)

  t.equal(plaintextForBob, 'hello bob')

  t.throws(function () {
    crypto.create_outbound_session(aliceAccount, 'bad identity key', bobsOneTimeKey)
  }, /INVALID_BASE64/, 'create olm outbound session with bad identity key')

  t.throws(function () {
    crypto.create_outbound_session(aliceAccount, bobsIdentityKey, 'bad one time key')
  }, /INVALID_BASE64/, 'create olm outbound session with bad one time key')

  t.throws(function () {
    crypto.create_inbound_session(bobAccount, 'bad one time key message')
  }, /BAD_MESSAGE_FORMAT/, 'create olm inbound session with one time key message')
})

test('session matches test', function (t) {
  t.plan(4)

  var aliceAccount = crypto.create_olm_account()
  var bobAccount = crypto.create_olm_account()

  crypto.create_account_one_time_keys(bobAccount, 100)

  var bobsIdentityKey = JSON.parse(crypto.identity_keys(bobAccount))['curve25519']
  var bobsOneTimeKey = JSON.parse(crypto.one_time_keys(bobAccount))['curve25519']['AAAAAQ']

  var sessionWithBob = crypto.create_outbound_session(aliceAccount, bobsIdentityKey, bobsOneTimeKey)
  t.ok(sessionWithBob)

  var ciphertextForBob = crypto.encrypt(sessionWithBob, 'hello bob')

  var sessionWithAlice = crypto.create_inbound_session(bobAccount, ciphertextForBob)
  t.ok(sessionWithAlice)

  var plaintextForBob = crypto.decrypt(sessionWithAlice, ciphertextForBob, 0)

  t.equal(plaintextForBob, 'hello bob')

  var secondCiphertextForBob = crypto.encrypt(sessionWithBob, 'hello bob')
  t.equal(crypto.matches_inbound_session(sessionWithAlice, secondCiphertextForBob), 1)
})

test('session pickle unpickle', function (t) {
  t.plan(5)

  var aliceAccount = crypto.create_olm_account()
  var bobAccount = crypto.create_olm_account()

  crypto.create_account_one_time_keys(bobAccount, 100)

  var bobsIdentityKey = JSON.parse(crypto.identity_keys(bobAccount))['curve25519']
  var bobsOneTimeKey = JSON.parse(crypto.one_time_keys(bobAccount))['curve25519']['AAAAAQ']

  var sessionWithBob = crypto.create_outbound_session(aliceAccount, bobsIdentityKey, bobsOneTimeKey)
  t.ok(sessionWithBob)

  var pickle = crypto.pickle_session(sessionWithBob)
  t.ok(pickle)

  sessionWithBob = crypto.unpickle_session(pickle)
  t.ok(sessionWithBob)

  var ciphertextForBob = crypto.encrypt(sessionWithBob, 'hello bob')

  var sessionWithAlice = crypto.create_inbound_session(bobAccount, ciphertextForBob)
  t.ok(sessionWithAlice)

  var plaintextForBob = crypto.decrypt(sessionWithAlice, ciphertextForBob, 0)

  t.equal(plaintextForBob, 'hello bob')
})
