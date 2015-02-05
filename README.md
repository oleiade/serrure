# Serrure
Serrure package provides an encryption/decryption toolkit library for golang.

Golang standard and official encryption libraries are pretty neat, clean and robust.
However these feel exposing too much complexity and low-level interfaces and operations for a daily usage in a project like [Trousseau](https://github.com/oleiade/trousseau).

Serrure was born from the need to provide a simple and easy to manipulate encryption layer to [Trousseau](https://github.com/oleiade/trousseau).

Serrure intends to expose a set of plain and high-level interfaces such as ``Encrypter`` and ``Decrypter`` and implementations hiding away most of the internals complexity to the user.

## Documentation

The library API is documented and demonstrated on [GoDoc](https://godoc.org/github.com/oleiade/serrure)

## Installation

**Nota**: If you intend to use *serrure* library in a production projects, please vendor your dependencies.

### Into the $GOPATH

```bash
$ go get github.com/oleiade/serrure
```

### Import it in your code

```go
import (
    "github.com/oleiade/serrure"            // interfaces
    "github.com/oleiade/serrure/openpgp"    // openpgp implementation
    "github.com/oleiade/serrure/aes"        // AES256 implementation
)
```

## Usage

### OpenPGP

```go
// First let's init an OpenPGPEncrypter.
// We let him know the path to our gnupg pubring file
// and a list of recipient (they must be present in your pubring)
// to the encryption; if you wanna be able to decrypt this message,
// you should be one of them...
ee, err := openpgp.NewOpenPGPEncrypter(
    "/home/my/user/.gnupg/pubring.gpg",
    []string{"AD4BF67", "B4E358F", "the@softwarehater.com"},
)
if err != nil {
    log.Fatal(err)
}

// Let's encrypt a cool song lyrics using it
ed, err := ee.Encrypt([]byte("abc 123 easy as do re mi"))
if err != nil {
    log.Fatal(err)
}

// Now ed holds your encrypted bytes
fmt.Println(string(ed))

// Thrust only what you see. Let's build a decrypter using
// using our gnupg secring file and the passphrase of the gpg key
// we want to use to later decrypt our message.
d, err := openpgp.NewOpenPGPDecrypter(
    "/home/my/user/.gnupg/secring.gpg",
    "My the@softwarehater.com private key's passphrase",
)
if err != nil {
    log.Fatal(err)
}

// And check that our recipients will acutally receive
// a Jackson5's song and not some horrible noise (I'm not pointing anyone)
pd, err := d.Decrypt(ed)
if err != nil {
    log.Fatal(err)
}

// Now pd holds your decrypted data and should
// print down a Jackson5's song
fmt.Println(string(pd))
```

### AES256

```go
// First let's init an AES25Encrypter.
// It takes as input the passphrase you wanna encrypt
// your bytes with any salt you'd wanna apply to it (if not just provide nil)
enc, err := aes.NewAES256Encrypter("mot de passe?", nil)
if err != nil {
    log.Fatal(err)
}

// Let's encrypt a good 80's song (yes, they're rare)
ed, err := enc.Encrypt([]byte("Sweet dreams are made of this. Who am I to disagree?"))
if err != nil {
    log.Fatal(err)
}

// Now ed holds your encrypted bytes
fmt.Println(string(ed))

// Let's build a decrypter, providing it our passphrase
// So we are then able to decrypt our bytes
dec := aes.NewAES256Decrypter("mot de passe?")
if err != nil {
    log.Fatal(err)
}

// Let's ensure that it's still Eurythmics singing in there
pd, err := dec.Decrypt(ed)
if err != nil {
    log.Fatal(err)
}

// TADA
fmt.Println(string(pd))
```

## Add your own

```go
// All you have to do is to implement the Encrypter and Decrypter interfaces
type Encrypter interface {
    Encrypt([]byte) ([]byte, error)
}

type Decrypter interface {
    Decrypt([]byte) ([]byte, error)
}
```

## Contribute

This library is developed with good intentions, and a lot of coffee. We are wide open (if not looking for) to others good intentions and talent to improve  the projects. 

Here's the common process:

1. Check for open issues or open a fresh issue to start a discussion around a feature idea or a bug.
2. Fork the [repository](https://github.com/oleiade/serrure) on GitHub to start making your changes to the master branch (or branch off of it).
3. Write tests which shows that the bug was fixed or that the feature works as expected.
4. Send a pull request and bug the maintainer until it gets merged and published. :) Make sure to add yourself to ``AUTHORS`` file.
