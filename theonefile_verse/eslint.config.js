import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["node_modules/**", "public/**", "data/**", ".testdata/**", ".tofcheck/**", "*.config.js"] },
  ...tseslint.configs.recommended,
  {
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrors: "none" }],
      "@typescript-eslint/no-empty-object-type": "off",
      "@typescript-eslint/no-unused-expressions": "off",
      "no-empty": "off",
      "no-control-regex": "off",
      "no-useless-escape": "off"
    }
  }
);
