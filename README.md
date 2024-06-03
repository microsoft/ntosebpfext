# NTOS eBPF Extensions

This repository contains source code libraries for accelerating the development of eBPF extensions for Windows, as they are documented in the [eBPF for Windows - eBPF extensions](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/eBpfExtensions.md) documentation.

The following eBPF extensions are included in this repository:

- `ntosebpfext`: An eBPF extension  that permits developers to leverage existing public
hooks in the Windows kernel to gather data and influence policy of the OS.

- [`neteventebpfext`](./docs/neteventebpfext.md): An eBPF extension that attaches to network events sourced by [NMR Provider Modules](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/initializing-and-registering-a-provider-module) that implement the `neteventebpfext`'s Network Provider Interface (NPI).

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

For more details on how to build and test, see [The contribution docs](CONTRIBUTING.md)

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
