const native: {
  getAppContainerProcessTokens(): string[];
} = require('../build/Release/w32appcontainertokens.node');

export const getAppContainerProcessTokens = native.getAppContainerProcessTokens;
