// |reftest| skip-if(!this.hasOwnProperty('BigInt')) -- BigInt is not enabled unconditionally
// Copyright (C) 2017 Josh Wolfe. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.
/*---
description: unsigned-right-shift operator ToNumeric with BigInt operands
esid: sec-unsigned-right-shift-operator-runtime-semantics-evaluation
info: After ToNumeric type coercion, unsigned-right-shift always throws for BigInt operands
features: [BigInt, Symbol.toPrimitive, computed-property-names]
---*/

assert.throws(TypeError, function() {
  Object(2n) >>> 0n;
}, "ToPrimitive: unbox object with internal slot");
assert.throws(TypeError, function() {
  0n >>> Object(2n);
}, "ToPrimitive: unbox object with internal slot");
assert.throws(TypeError, function() {
  ({
    [Symbol.toPrimitive]: function() {
      return 2n;
    }
  }) >>> 0n;
}, "ToPrimitive: @@toPrimitive");
assert.throws(TypeError, function() {
  0n >>> {
    [Symbol.toPrimitive]: function() {
      return 2n;
    }
  };
}, "ToPrimitive: @@toPrimitive");
assert.throws(TypeError, function() {
  ({
    valueOf: function() {
      return 2n;
    }
  }) >>> 0n;
}, "ToPrimitive: valueOf");
assert.throws(TypeError, function() {
  0n >>> {
    valueOf: function() {
      return 2n;
    }
  };
}, "ToPrimitive: valueOf");
assert.throws(TypeError, function() {
  ({
    toString: function() {
      return 2n;
    }
  }) >>> 0n;
}, "ToPrimitive: toString");
assert.throws(TypeError, function() {
  0n >>> {
    toString: function() {
      return 2n;
    }
  };
}, "ToPrimitive: toString");

reportCompare(0, 0);
