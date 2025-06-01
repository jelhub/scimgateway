//
// File: samlAssertion.ts
// Purpose: create SAML token assertion that can be used by OAuth token request having grant type saml2-bearer
// Based on: https://github.com/edersouza38/insomnia-plugin-sfsf-samlassertion
//
// MIT License
//
// Copyright (c) 2023 edersouza38
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

// @ts-expect-error type declaration file not found
import { Saml20 as saml } from 'saml'
import crypto from 'node:crypto'

export const samlAssertionUtils = {
  formatPrivateKey: function (input: string) {
    // Validate PEM keys:
    const keyArmor = /-----(BEGIN |END )(.*?) KEY-----/g
    let v: any = [...input.matchAll(keyArmor)]
    if (v.length > 0) {
      if (v.length !== 2 || v[0][2] !== v[1][2] || v[0][2] !== 'PRIVATE') {
        throw new Error('Invalid PEM private key. Make sure that the armoring is consistent and the PEM key is from the type "PRIVATE".')
      }
      return input.replace(/\r?\n|\r/g, '')
    }

    // Verify whether key was generated directly in SFSF:
    const d = Buffer.from(input, 'base64').toString('utf-8')
    v = d.split('###')
    if (v.length === 2) {
      input = v[0]
    }
    return `-----BEGIN PRIVATE KEY-----${input}-----END PRIVATE KEY-----`
  },

  formatCertificate: function (input: string) {
    // Validate PEM keys:
    const keyArmor = /-----(BEGIN |END )(.*?)-----/g
    let v: any = [...input.matchAll(keyArmor)]
    if (v.length > 0) {
      if (v.length !== 2 || v[0][2] !== v[1][2]) {
        throw new Error('Invalid PEM certificate. Make sure that the armoring is consistent.')
      }
      return input.replace(/\r?\n|\r/g, '')
    }

    // Verify whether key was generated directly in SFSF:
    const d = Buffer.from(input, 'base64').toString('utf-8')
    v = d.split('###')
    if (v.length === 2) {
      input = v[0]
    }
    return `-----BEGIN CERTIFICATE-----${input}-----END CERTIFICATE-----`
  },

  delay: function (time: number) {
    return new Promise(resolve => setTimeout(resolve, time))
  },

  userIdentifierFormat: {
    userId: 'userId',
    userName: 'userName',
    eMail: 'e-Mail',
  },
}

export const samlAssertion = {
  name: 'samlAssertionSFSF',
  displayName: 'SAML Assertion - SFSF',
  description: 'Create a SAML Assertion for SFSF OAuth2SAMLAssertion flow.',
  args: [
    {
      displayName: 'X.509 Certificate',
      description: 'X.509 Certificate used to identify the SAML IdP',
      type: 'string',
      placeholder: '-----BEGIN CERTIFICATE-----',
    },
    {
      displayName: 'Private Key',
      description: 'Private Key used to sign the SAML Assertion',
      type: 'string',
      placeholder: '-----BEGIN PRIVATE KEY-----',
    },
    {
      displayName: 'SAML Issuer',
      description: 'Name of the IdP issuing the SAML Assertion',
      type: 'string',
      defaultValue: 'local.insomnia.com',
    },
    {
      displayName: 'Lifetime in seconds',
      description: 'Lifetime of the SAML Assertion in seconds',
      type: 'number',
      defaultValue: 600,
    },
    {
      displayName: 'Client Id',
      description: 'Registered Client Id in SFSF',
      type: 'string',
      placeholder: 'OWE1Yzg0NTMyOGJlY2M4NWRiZGFiMGE3MTI5MA',
    },
    {
      displayName: 'User Identifier',
      description: 'User Identifier',
      type: 'string',
      placeholder: 'Username',
    },
    {
      displayName: 'User Identifier Format',
      description: 'User Identifier Format',
      type: 'enum',
      placeholder: 'User Identifier Format',
      defaultValue: samlAssertionUtils.userIdentifierFormat.userId,
      options: [
        {
          displayName: 'User ID',
          value: samlAssertionUtils.userIdentifierFormat.userId,
        },
        {
          displayName: 'Username',
          value: samlAssertionUtils.userIdentifierFormat.userName,
        },
        {
          displayName: 'E-Mail',
          value: samlAssertionUtils.userIdentifierFormat.eMail,
        },
      ],
    },
    {
      displayName: 'OAuth Token Endpoint',
      description: 'SFSF OAuth Token Endpoint',
      type: 'string',
      placeholder: 'Username',
    },
    {
      displayName: 'Audience',
      description: 'Audience of the SAML Assertion',
      type: 'string',
      defaultValue: 'www.successfactors.com',
    },
    {
      displayName: 'Delay (Seconds)',
      description: 'Useful when the request is reaching the endpoint before the "validNotBefore" date from SAML assertion.',
      type: 'number',
      defaultValue: 0,
    },
  ],

  async run(
    context: any,
    cert: any,
    key: any,
    issuer: any,
    lifetime: any,
    clientId: any,
    nameId: any,
    userIdentifierFormat: any,
    tokenEndpoint: any,
    audience: any,
    delay: any,
  ) {
    const samlAttributes: Record<string, any> = {
      api_key: clientId,
    }

    let nameIdentifierFormat
      = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'

    switch (userIdentifierFormat) {
      case samlAssertionUtils.userIdentifierFormat.eMail:
        nameIdentifierFormat
          = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        break
      case samlAssertionUtils.userIdentifierFormat.userName:
        samlAttributes.use_username = 'true'
        break
      default:
        break
    }
    const options = {
      cert: samlAssertionUtils.formatCertificate(cert),
      key: samlAssertionUtils.formatPrivateKey(key),
      issuer: issuer,
      lifetimeInSeconds: lifetime,
      audiences: audience,
      attributes: samlAttributes,
      nameIdentifier: nameId,
      nameIdentifierFormat: nameIdentifierFormat,
      recipient: tokenEndpoint,
      sessionIndex: '_' + crypto.randomUUID(),
    }

    const assertionBuff = Buffer.from(saml.create(options))
    const assertion = assertionBuff.toString('base64')

    if (delay > 0) {
      await samlAssertionUtils.delay(delay * 1000)
    }
    return assertion
  },
}

export default samlAssertion
