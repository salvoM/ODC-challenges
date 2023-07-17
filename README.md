# ODC-challenges
This repo contains the binary challenges that I solved during the Offensive and Defensive Cybersecurity class (2021/22).

## Shellcode
Developed few shellcodes manually. Usually, there were constraint such as certain forbiden bytes value or working with stdout closed.

## Mitigations
Mitigations employed in modern devices, such as Data Execution Prevetion, Not eXecutable stack, stack canaries, and Address Space Layout Randomization,
can still be bypassed if there are coding errors.
In fact, they are mitigations that only make an adversary work harder.

## ROP
ROP is a technique used to bypass security mechanisms like Data Execution Prevention (DEP) by leveraging existing snippets of code, known as gadgets, in a program's memory.
The goal is to construct a chain of gadgets from the existing code to perform unintended actions.

## Reversing
Reversing challenges usually employ anti-debug techniques and often perform frequent action in a non-standard way (custom implementation of several routines).
We have seen how we can patch ELF executable files and how GDB can be scripted to easily perform some actions.

## Symbolic
We have seen how symbolic execution can easily beat crackme challenges, when one writes the appropriate constraints.

## Heap
We studied the Libc allocator, how the deallocation works, and how it can be exploited when programming mistakes happen.
We have seen use-after-free, double-free and other common vulnerabilites when dealing with the heap.

## Packer
We have seen a toy malware sample that was packed. The malware continuously packs/unpacks chunks of code that executes, so we had to dump the memory several times in different points of the executions.
Then we had to reverse-engineer the single chunks until finally being able to put all the pieces together.


# Solutions
My solutions are (for now) omitted because this year (2022/23) challenges are almost the same as the previous year ones.
