securestring
============

A C++ String-like-class that does not save data as plain-text in memory. It makes live analysis of memory more difficult, as well as forensic analysis, as the content is made sure to be wiped from memory when the instance is deleted.
