Dashcore Payment Protocol
==============================

[![NPM Package](https://img.shields.io/npm/v/@dashevo/dashcore-payment-protocol.svg?style=flat-square)](https://www.npmjs.org/package/@dashevo/dashcore-payment-protocol)
[![Build Status](https://img.shields.io/travis/dashevo/dashcore-payment-protocol.svg?branch=master&style=flat-square)](https://travis-ci.org/dashevo/dashcore-payment-protocol)
[![Coverage Status](https://img.shields.io/coveralls/dashevo/dashcore-payment-protocol.svg?style=flat-square)](https://coveralls.io/r/dashevo/dashcore-payment-protocol)

A module for [dashcore](https://github.com/dashevo/dashcore) that implements [Payment Protocol](https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki) and other related BIPs.

## Getting Started

This library is distributed in both the npm and bower packaging systems.

```sh
npm install dashcore-lib
npm install dashcore-payment-protocol
```

There are many examples of how to use it on the developer guide [section for payment protocol](https://bitcore.io/api/paypro). For example, the following code would verify a payment request:

```javascript
var PaymentProtocol = require('dashcore-payment-protocol');

var body = PaymentProtocol.PaymentRequest.decode(rawbody);
var request = new PaymentProtocol().makePaymentRequest(body);

var version = pr.get('payment_details_version');
var pki_type = pr.get('pki_type');
var pki_data = pr.get('pki_data');
var serializedDetails = pr.get('serialized_payment_details');
var signature = pr.get('signature');

// Verify the signature
var verified = request.verify();
```

## Contributing

See [CONTRIBUTING.md](https://github.com/dashevo/dashcore/blob/master/CONTRIBUTING.md) on the main dashcore repo for information about how to contribute.

## License

Code released under [the MIT license](https://github.com/dashevo/dashcore/blob/master/LICENSE).

Copyright 2013-2015 BitPay, Inc. Bitcore is a trademark maintained by BitPay, Inc.
