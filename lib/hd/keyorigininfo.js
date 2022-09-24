'use strict';

const assert = require('assert');
const common = require('./common');
const bio = require('bufio');
const hash160 = require('bcrypto/lib/hash160');
const WalletKey = require('../wallet/walletkey');

/**
 * Helper class to represent hd key path for arbitrary wallets.
 * @property {Number} fingerPrint - master key fingerprint (uint32)
 * @property {Array} path - bip32 derivation path in uint32 array
 */

class KeyOriginInfo {
  /**
   * Create a KeyOriginInfo object.
   * @constructor
   * @param {Object} options
   * @param {Number} options.fingerPrint
   * @param {Number[]} options.path
   */

  constructor(options) {
    this.fingerPrint = -1;
    this.path = [];
    if (options) {
      this.fromOptions(options);
    }
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    assert(options, 'requires options');
    if (options.fingerPrint) {
      assert(
        (options.fingerPrint >>> 0) === options.fingerPrint,
        'fingerPrint must be uint32'
      );
      this.fingerPrint = options.fingerPrint;
    }
    if (options.path) {
      if (Array.isArray(options.path)) {
        assert(
          options.path.every(p => (p >>> 0) === p),
          'all path index must be uint32'
        );
        this.path = options.path;
      } else {
        this.path = common.parsePath(options.path, true);
      }
    }
    return this;
  }

  /**
   * Instantiate from options object.
   * @param {Object} options
   * @returns {HDPublicKey}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Compare against self.
   * @param {KeyOriginInfo} keyInfo
   * @returns {Boolean}
   */

  equals(keyInfo) {
    assert(KeyOriginInfo.isKeyOriginInfo(keyInfo));
    if (this.fingerPrint !== keyInfo.fingerPrint)
      return false;
    for (const i in this.path) {
      if (this.path[i] !== keyInfo.path[i])
        return false;
    }
    return true;
  }

  /**
   * Inspect KeyOriginInfo object.
   * @returns {Object}
   */

  inspect() {
    return this.format();
  }

  /**
   * Convert the KeyOriginInfo (self) to a more user-friendly object.
   * @returns {Object}
   */

  format() {
    let path = 'm';
    for (const p of this.path) {
      const hardened = (p & common.HARDENED) ? '\'' : '';
      path += `/${p & 0x7fffffff}${hardened}`;
    }
    return {
      fingerPrint: this.fingerPrint,
      path
    };
  }

  /**
   * Instantiate from serialized data.
   * @param {Buffer} data
   * @return {KeyOriginInfo}
   */

  static fromRaw(data) {
    return new this().fromRaw(data);
  }

  /**
   * Inject properties from serialized data.
   * @param {Buffer} data
   * @return {KeyOriginInfo}
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  };

  /**
   * Instantiate from BufferedReader.
   * @param {BufferReader} br
   * @return {KeyOriginInfo}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Inject properties from BufferedReader.
   * @param {BufferReader} br
   * @return {KeyOriginInfo}
   */

  fromReader(br) {
    this.fingerPrint = br.readU32BE();
    while (br.left()) {
      this.path.push(br.readU32());
    }
    return this;
  }

  /**
   * Serialize.
   * @return {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  /**
   * Write to BufferWriter.
   * @param {BufferWriter} bw
   * @return {BufferWriter}
   */

  toWriter(bw) {
    bw.writeU32BE(this.fingerPrint);
    for (const p of this.path) {
      bw.writeU32(p);
    }
    return bw;
  }

  /**
   * Convert to a more json-friendly object.
   * @returns {Object}
   */

  toJSON() {
    return {
      fingerPrint: this.fingerPrint,
      path: this.path
    };
  }

  /**
   * Instantiate from jsonified object.
   * @param {Object} json
   * @return {KeyOriginInfo}
   */

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  /**
   * Inject properties from jsonified object.
   * @param {Object} json
   * @return {KeyOriginInfo}
   */

  fromJSON(json) {
    if (json.fingerPrint) {
      assert((json.fingerPrint >>> 0) === json.fingerPrint);
      this.fingerPrint = json.fingerPrint;
    }

    if (json.path) {
      if (Array.isArray(json.path) && json.path.length > 0) {
        for (const p of json.path) {
          assert((p >>> 0) === p);
          this.path.push(p);
        }
      } else {
        this.path = common.parsePath(json.path, true);
      }
    }

    return this;
  }

  /**
   * Check if object is a KeyOriginInfo.
   * @param {Object} obj
   * @return {Boolean}
   */

  static isKeyOriginInfo(obj) {
    return obj instanceof KeyOriginInfo;
  }

  /**
   * Clone from self.
   * @return {KeyOriginInfo}
   */

  clone() {
    const path = this.path.slice();
    return new KeyOriginInfo({fingerPrint: this.fingerPrint, path});
  }

  /**
   * Clear all info.
   */

  clear() {
    this.fingerPrint = -1;
    this.path = [];
  }

  /**
   * Calculate serialization size.
   * @returns {Number}
   */

  getSize() {
    return 4 + this.path.length * 4;
  }

  /**
   * Instantiate from WalletKey.
   * @param {WalletKey} wk
   * @return {KeyOriginInfo}
   */

  static fromWalletKey(wk) {
    return new this().fromWalletKey(wk);
  }

  /**
   * Inject properties from WalletKey.
   * @param {WalletKey} wk
   * @return {KeyOriginInfo}
   */

  fromWalletKey(wk) {
    assert(WalletKey.isWalletKey(wk));
    const fp = hash160.digest(wk.publicKey);
    this.fingerPrint = fp.readUInt32BE(0, true);
    this.path.push(wk.account | common.HARDENED);
    this.path.push(wk.branch);
    this.path.push(wk.index);
    return this;
  }
}

module.exports = KeyOriginInfo;
