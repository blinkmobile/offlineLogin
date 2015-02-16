/*eslint-env node*/
'use strict';
var requirejs = require('requirejs');
var test = require('tape');
var fakeDB = {};
var getRecord;
var setRecord;
var auth;
var key = 'authData';

requirejs.config({
    nodeRequire: require,
    paths: {
      authentication: 'authentication'
    }
});

requirejs(['authentication'], function (Authentication) {
  getRecord = function (callback) {
    if (fakeDB[key]) {
      callback(null, fakeDB[key]);
    } else {
      callback(null, null);
    }
  };

  setRecord = function (value, callback) {
    fakeDB[key] = value;
    callback(null, value);
  };

  auth = new Authentication({
    getRecord: getRecord,
    setRecord: setRecord
  });

  test('Authentication is a constructor function', function (t) {
    t.plan(1);

    t.equal(typeof Authentication, 'function', 'Authentication');
  });

  test('Authentication accepts object containing DB handlers', function (t) {
    t.plan(2);

    var customAuth = new Authentication({
      setRecord: 'set',
      getRecord: 'get'
    });

    t.equal(customAuth.setRecord, 'set', '#setRecord handler stored');
    t.equal(customAuth.getRecord, 'get', '#getRecord handler stored');

  });

  test('Authentication has the functions specified in the spec', function (t) {
    t.plan(3);
    t.ok(auth.getCurrent, '#getCurrent');
    t.ok(auth.setCurrent, '#setCurrent');
    t.ok(auth.authenticate, '#authenticate');
  });

  test('#getCurrent', function (t) {
    t.plan(3);

    var errorHandler = function (err) {console.log(err);};

    fakeDB = {};
    auth.getCurrent(function (data) {
      t.false(data, 'First argument should be falsy when no current user');
    }, errorHandler);

    auth.setCurrent({
      principal: 'getCurrent test',
      credential: 'test',
      expiry: new Date(1)
    }, function () {
      auth.getCurrent(function (data) {
        t.false(data, 'First argument should be falsy when use timed out');
      }, errorHandler);
    });

    auth.setCurrent({
      principal: 'getCurrent test',
      credential: 'test',
      expiry: new Date(99999999999999)
    }, function () {
      auth.getCurrent(function (data) {
        t.deepEqual(data, {
          principal: 'getCurrent test',
          expiry: new Date(99999999999999)
        }, 'User document should contain principal and expiry when logged in');
      }, errorHandler);
    });
  });

  test('#setCurrent', function (t) {
    t.plan(7);

    var userRecord = {
      principal: 'Test Principal',
      credential: 'password',
      expiry: new Date(),
      hashAlgorithm: ''
    };

    auth.setCurrent(userRecord, function () {
      t.pass('#onSuccess called');
      t.notEqual(fakeDB[key].credential, 'password', 'Credential should be SHA1 hashed');
      t.equal(fakeDB[key].principal, userRecord.principal, 'Principal should match');
      t.equal(fakeDB[key].expiry, userRecord.expiry, 'Expiry should match');
    });

    // Validation
    auth.setCurrent({
      credential: 'Test',
      expiry: new Date()
    }, null, function (err) {
      t.equal(typeof err, 'object');
    });

    auth.setCurrent({
      principal: 'Test',
      expiry: new Date()
    }, null, function (err) {
      t.equal(typeof err, 'object');
    });

    auth.setCurrent({
      principal: 'Test',
      credential: 'Test'
    }, null, function (err) {
      t.equal(typeof err, 'object');
    });
  });

  test('#authenticate', function (t) {
    t.plan(5);

    var principal = 'authenticate test';
    var credential = 'test';
    var errorHandler = function (err) {console.log(err);};

    fakeDB = {}
    auth.authenticate({
        principal: principal,
        credential: credential
      }, function (data) {
        t.false(data, 'First argument should be falsy when use timed out');
      }, errorHandler);

    auth.setCurrent({
      principal: principal,
      credential: credential,
      expiry: new Date(1)
    }, function () {
      auth.authenticate({
        principal: principal,
        credential: credential
      }, function (data) {
        t.false(data, 'First argument should be falsy when user timed out');
      }, errorHandler);
    });

    auth.setCurrent({
      principal: principal,
      credential: credential,
      expiry: new Date(99999999999999)
    }, function () {
      auth.getCurrent(function (data) {
        t.deepEqual(data, {
          principal: principal,
          expiry: new Date(99999999999999)
        }, 'User document should contain principal and expiry when logged in');
      }, errorHandler);
    });


    // Validation
    auth.authenticate({
      credential: 'Test'
    }, null, function (err) {
      t.equal(typeof err, 'object');
    });

    auth.authenticate({
      principal: 'Test'
    }, null, function (err) {
      t.equal(typeof err, 'object');
    });
  });
});
