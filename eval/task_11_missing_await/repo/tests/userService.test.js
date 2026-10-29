const { fetchUserName } = require("../src/userService");

test("fetchUserName returns Alice for id 1", async () => {
  const name = await fetchUserName(1);
  expect(name).toBe("Alice");
});

test("fetchUserName returns Bob for id 2", async () => {
  const name = await fetchUserName(2);
  expect(name).toBe("Bob");
});

test("fetchUserName returns null for unknown id", async () => {
  const name = await fetchUserName(99);
  expect(name).toBeNull();
});
