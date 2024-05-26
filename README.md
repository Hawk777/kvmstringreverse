What is this?
=============

`kvmstringreverse` reverses the data passed to it on standard input, sending
the reversed data to standard output, as long as the data is ≤64 kiB. It does
this by creating a virtual machine via Linux’s KVM driver, loading a small
bare-metal assembly language array-reversal routine (built from `guest.asm`)
into it, and then feeding the data into and out of the virtual machine via I/O
ports.

Why?
====

Because.

How do I run it?
================

Compile it with `make`. You’ll need GCC and Nasm. Run it and feed some text
into standard input (e.g. `echo hello | ./kvmstringreverse`).

Can I steal it?
===============

You probably *shouldn’t*, but you *can*. I hereby put this in the public
domain.
