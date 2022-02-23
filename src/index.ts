import { join } from "path";

let native:
  | undefined
  | {
      getAppContainerProcessTokens(): string[];
    };

const getModule = () => {
  if (process.platform !== "win32") {
    return;
  }

  native ??= require("../build/Release/w32appcontainertokens.node");
  return native;
};

export const getAppContainerProcessTokens = (suffix: string) =>
  getModule()
    ?.getAppContainerProcessTokens()
    .map((path) => join(path, suffix));
