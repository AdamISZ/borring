# borring

**UPDATE: Removed bitcoin directory; this serves to prevent misguided usage of this code as anything other than educational/pseudocode! Do NOT attempt to use this in real projects!**

*Update: algorithm now confirmed to be compatible with that in Elements Alpha*.

Basic implementation of Borromean ring signatures in Python, for learning. I wrote this to aid my own understanding; it may also help you. It is not intended to be functional or fit for any other purpose.

`python borring.py -h` for usage syntax.

See [the Borromean ring signatures paper](https://github.com/Blockstream/borromean_paper/raw/master/borromean_draft_0.01_34241bb.pdf) for the theory.

The idea is to have a signature over (key1 or key2 or key3 ...) AND (key4 or key5 or key6 ...) AND ... , for an arbitrary number of keys in each 'or' loop and an arbitrary number of loops.

The keys used are Bitcoin (secp256k1 by default) keys. The public keys for verification of a signature are to be stored in a text file in hex format, and the corresponding private key for **one** of the public keys in each "OR loop" must be stored in hex format in a second file (any in the loop; but only one); sample key files are created by using the -g option, so there's no need to mess around finding keys from somewhere else.

The message to be signed must be specified as the single argument to the script, as a single string.

For Bitcoin operations (public/private and ECC operations) a snapshot of [pybitcointools](https://github.com/vbuterin/pybitcointools) was used; but see first 'update' note above.


## Example (4 OR loops, each with 7 keys)

````
~/DevRepos/borring$ python borring.py -g -N 4 -M 7
generating
~/DevRepos/borring$ python borring.py -w asigfile 'blah blah blah'
writing sig to file: asigfile
signature length: 928
~/DevRepos/borring$ python borring.py -e asigfile 'blah blah blah'
Now trying to verify
verification success
7383ec2d299131d473c1d969af10a88da9e8d4812d877d1d20f99ed2521f77b8
7383ec2d299131d473c1d969af10a88da9e8d4812d877d1d20f99ed2521f77b8
````
