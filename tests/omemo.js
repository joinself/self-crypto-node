// Copyright 2020 Self Group Ltd. All Rights Reserved.

var test = require('tape')
var crypto = require('../')

test('group session encrypt decrypt test', function (t) {
  t.plan(5)

  var aliceAccount = crypto.create_olm_account()
  var bobAccount = crypto.create_olm_account()

  // crypto.create_account_one_time_keys(bobAccount, 100)
  // var bobsIdentityKey = JSON.parse(crypto.identity_keys(bobAccount))['curve25519']
  // var bobsOneTimeKey = JSON.parse(crypto.one_time_keys(bobAccount))['curve25519']['AAAAAQ']

  // Force reeal values for all inputs
  var bobsIdentityKey = 'FPKOZgWjnnqA6IaG7d2odNBV0TdltnQhDbXPTq7xSMM'
  var bobsOneTimeKey = 'SxhwElBIqJmd1PG/YaCApGiXp5zzSGqm7IoYdkNW6kk'
  var bobID = '10377379035:dA4mRcImQ4KPJNsqPR3oXe'
  var aliceID = 'abb6f604-b28d-4c15-ac01-84df3305cf92:1'

  // ENCRYPTION (alice)
  var sessionWithBob = crypto.create_outbound_session(aliceAccount, bobsIdentityKey, bobsOneTimeKey)
  t.ok(sessionWithBob)

  var groupSessionWithBob = crypto.create_group_session(aliceID)
  crypto.add_group_participant(groupSessionWithBob, bobID, sessionWithBob)

  console.log(" - encrypting 'hello bob and everyone else'")
  var groupCiphertext = crypto.group_encrypt(groupSessionWithBob, 'hello bob and everyone else')
  t.ok(groupCiphertext)
  console.log(` - encrypted '${groupCiphertext}'`)

  // DECRYPTING (bob)
  var ciphertextForBob = JSON.parse(groupCiphertext)['recipients'][bobID]['ciphertext']
  t.ok(ciphertextForBob)

  var sessionWithAlice = crypto.create_inbound_session(bobAccount, ciphertextForBob)
  t.ok(sessionWithAlice)

  var groupSessionWithAlice = crypto.create_group_session(bobID)
  crypto.add_group_participant(groupSessionWithAlice, aliceID, sessionWithAlice)

  console.log(` - decrypting '${groupCiphertext}'`)
  var plaintextForBob = crypto.group_decrypt(groupSessionWithAlice, aliceID, groupCiphertext)
  console.log(` - decrypted '${plaintextForBob}'`)

  t.equal(plaintextForBob, 'hello bob and everyone else')

  crypto.destroy_group_session(groupSessionWithAlice)
  crypto.destroy_group_session(groupSessionWithBob)
})
