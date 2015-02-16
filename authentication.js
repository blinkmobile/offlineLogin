/*eslint-env amd*/
define(
  ['sjcl'], function (sjcl) {
    'use strict';

    var Authentication = function (options) {
      options = options || {};
      this.getRecord = options.getRecord || null;
      this.setRecord = options.setRecord || null;
    };

    Authentication.prototype.getCurrent = function (onSuccess, onError) {
      this.getRecord(function(err, data) {
        if (err) {
          return onError(err);
        }

        if (!data) {
          return onSuccess(null);
        }

        if (data.expiry < new Date()) {
          return onSuccess(null);
        }

        if (data.principal && data.expiry) {
          data = {
            principal: data.principal,
            expiry: data.expiry
          };
        }

        onSuccess(data);
      });
    };

    Authentication.prototype.setCurrent = function (data, onSuccess, onError) {
      if (!data.principal || !data.credential || !data.expiry) {
        return onError(new Error('Missing required attribute(s)'));
      }

      data.credential = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(data.credential));

      this.setRecord(data, function () {
        onSuccess();
      });
    };

    Authentication.prototype.authenticate = function (data, onSuccess, onError) {
      if (!data.principal || !data.credential) {
        return onError(new Error('Missing required attribute(s)'));
      }

      var hashedCredential = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(data.credential));

      this.getRecord(function (err, cached) {
        if (err) {
          return onError(err);
        }

        if (!cached) {
          return onSuccess(null);
        }

        if (cached.expiry < new Date()) {
          return onSuccess(null);
        }

        if (data.principal === cached.principal &&
          hashedCredential === cached.credential) {
            onSuccess({
              principal: cached.principal,
              expiry: cached.expiry
            });
          }
      });
    };

    return Authentication;
  }
);
