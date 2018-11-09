'use strict'

const base64js = require('base64-js')

class Crypt {
  /**
   * Converts a JS string to an UTF-8 uint8array.
   *
   * @static
   * @param {String} str 16-bit unicode string.
   * @return {Uint8Array} UTF-8 Uint8Array.
   * @memberof Crypt
   */
  static stringToArrayBufferInUtf8 (str) {
    // if not browser env, then require node.js's util. otherwise just use window's
    const TextEncoder = (typeof window === 'undefined') ? require('util').TextEncoder : window.TextEncoder
    // always utf-8
    let encoder = new TextEncoder()
    return encoder.encode(str)
  }

  /**
   * Converts an UTF-8 uint8array to a JS string.
   *
   * @static
   * @param {Uint8Array} strBuffer UTF-8 Uint8Array.
   * @return {String} 16-bit unicode string.
   * @memberof Crypt
   */
  static utf8ArrayBufferToString (strBuffer) {
    // if not browser env, then require node.js's util. otherwise just use window's
    const TextDecoder = (typeof window === 'undefined') ? require('util').TextDecoder : window.TextDecoder
    let decoder = new TextDecoder('utf-8')
    return decoder.decode(strBuffer)
  }

  /**
   * crypt a utf8 byteArray to base64 string
   *
   * @static
   * @param {Uint8Array} strBuffer UTF-8 Uint8Array.
   * @returns {String} base64 str
   * @memberof Crypt
   */
  static arrayBufferToBase64 (strBuffer) {
    return base64js.fromByteArray(strBuffer)
  }

  /**
   * crypt base64 stringa to utf8 byteArray
   *
   * @static
   * @param {String} base64 str
   * @returns {Uint8Array} strBuffer UTF-8 Uint8Array.
   * @memberof Crypt
   */
  static base64ToArrayBuffer (base64) {
    return base64js.toByteArray(base64)
  }
}

module.exports = Crypt
