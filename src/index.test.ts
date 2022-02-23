import * as assert from "assert";
import { getAppContainerProcessTokens } from "./index";

assert(getAppContainerProcessTokens("Hello") instanceof Array);
