SecureString
============

SecureString is a C++ class that does not save data as plain-text in memory. It makes live analysis of memory more difficult, as well as forensic analysis, as the content is made sure to be wiped from memory when the instance is deleted.

It is provided as open-source (MIT-license) and is freely available to anyone! It is provided "as is" and I make no guarantees that the code is bug-free or functional in all senarios.

Where to get it?
----------------

The ~~Bitbucket~~ Github project is located [here](https://github.com/alex-caelus/SecureString), or you can download the source below:

How do I use it?
----------------

Just clone the repository as a git submodule using the `git submodule add https://github.com/alex-caelus/SecureString.git SecureString` command into your source directory. Then `#include "SecureString/SecureString.h"` in all source files where you want to use the class.

Where do i report bugs/feature requests?
----------------------------------------

[Here](https://github.com/alex-caelus/SecureString/issues), please check wheather or not a simmilar issue/request already exists before you posts

How do I contribute?
--------------------

Visit the GitHub project and make a fork of it, make any changes you want and then make a pull request and I'll look into it :).

Change Log
----------

Date       | Version | Description
-----------|---------|------------
2014-05-08 | 1.1     | Switched to GitHub, added MIT licence.
2012-05-21 | 1.0     | Project uploaded to www.caelus.org/proj/securestring and bitbucket.org/Caelus/securestring