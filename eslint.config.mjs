// @ts-check
import eslint from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";
import stylistic from "@stylistic/eslint-plugin";
import prettier from "eslint-config-prettier";

export default defineConfig(
	eslint.configs.recommended,
	tseslint.configs.strict,
	stylistic.configs.recommended,
	prettier,
	{
		rules: {
			semi: ["error", "always"],
			indent: ["error", "tab", { SwitchCase: 1 }],
			curly: ["error", "all"],
		},
		ignores: ["bun.lock", "node_modules/"],
	},
);
