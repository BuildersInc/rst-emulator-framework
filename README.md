# RST Assembly Emulation and Testing Framework

This emulation and testing framework has been developed to test assembler code created by students.

It can be integrated into existing CI/CD pipelines or set up from scratch to test code in an automated environment.
In our setup here at the Ostfalia we use Artemis.

The built-in Docker container is ready to use immediately.

This framework is based on the [Unicorn emulation engine](https://github.com/unicorn-engine/unicorn).

## Limitations

This Framework is only tested and prepared for the ARM-Instruction set.
A configuration change is possible but not fully supported at the moment.
