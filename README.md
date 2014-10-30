## sectsum: List the sha1 sums of an ELF (library, object, or executable)

### What
sectsum lists the ELF file's sections and the SHA1 sum of the given sections.
So what... you might be saying, I can craft a objdump version of this and pipe
the results to sha1sum.  Sure, but here's a program that does it too, whoptie
doo!

### Depends
Depends on openssl: https://www.openssl.org

### Build
Compile by merely running '''make''' in the sectsum directory

### Run
The only required argument is the object file, executable, or library file.
Run sectsum without arguments to get the help.

### Contact
Matt Davis
mattdavis9@gmail.com
