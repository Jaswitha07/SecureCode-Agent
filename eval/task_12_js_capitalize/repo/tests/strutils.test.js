const { capitalize } = require("../src/strutils");

test("capitalize lowercases rest", () => {
  expect(capitalize("hELLO")).toBe("Hello");
});

test("capitalize handles all-lowercase", () => {
  expect(capitalize("world")).toBe("World");
});

test("capitalize handles single char", () => {
  expect(capitalize("a")).toBe("A");
});

test("capitalize handles empty string", () => {
  expect(capitalize("")).toBe("");
});
