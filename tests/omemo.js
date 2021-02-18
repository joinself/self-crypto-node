// Copyright 2020 Self Group Ltd. All Rights Reserved.

var test = require('tape')
var crypto = require('../')

test('group session encrypt decrypt test', function (t) {
  t.plan(5)

  var aliceAccount = crypto.create_olm_account()
  var bobAccount = crypto.create_olm_account()

  crypto.create_account_one_time_keys(bobAccount, 100)

  var bobsIdentityKey = JSON.parse(crypto.identity_keys(bobAccount))['curve25519']
  var bobsOneTimeKey = JSON.parse(crypto.one_time_keys(bobAccount))['curve25519']['AAAAAQ']

  var sessionWithBob = crypto.create_outbound_session(aliceAccount, bobsIdentityKey, bobsOneTimeKey)
  t.ok(sessionWithBob)

  var groupSessionWithBob = crypto.create_group_session('alice')
  crypto.add_group_participant(groupSessionWithBob, 'bob', sessionWithBob)

  var groupCiphertext = crypto.group_encrypt(groupSessionWithBob, 'hello bob and everyone else')
  t.ok(groupCiphertext)

  var ciphertextForBob = JSON.parse(groupCiphertext)['recipients']['bob']['ciphertext']
  t.ok(ciphertextForBob)

  var sessionWithAlice = crypto.create_inbound_session(bobAccount, ciphertextForBob)
  t.ok(sessionWithAlice)

  var groupSessionWithAlice = crypto.create_group_session('bob')
  crypto.add_group_participant(groupSessionWithAlice, 'alice', sessionWithAlice)

  var plaintextForBob = crypto.group_decrypt(groupSessionWithAlice, 'alice', groupCiphertext)

  t.equal(plaintextForBob, 'hello bob and everyone else')

  crypto.destroy_group_session(groupSessionWithAlice)
  crypto.destroy_group_session(groupSessionWithBob)
})
