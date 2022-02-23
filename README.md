# @vscode/win32-app-container-tokens

Native win32 Node.js addon to retrieve named pipes from app containers. This is used to implement webview2 debugging inside UWPs.

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

### Building

This is a native project that can be built on Windows. It uses the [node-addon-api](https://github.com/nodejs/node-addon-api).

1. Clone it!
1. Run `npm install`
1. Run `npm run build` to build the native code.

When using VS Code, you'll want to add the following include paths to the C++ configuration (via the **C/C++: Edit Configurations (UI)** command):

- `<folder>/node_modules/node-addon-api`
- `C:/Users/<USER>/AppData/Local/node-gyp/Cache/<NODE VERSION>/include/node`

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
