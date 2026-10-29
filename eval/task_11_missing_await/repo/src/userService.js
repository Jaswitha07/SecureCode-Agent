// userService.js
async function getUserById(id) {
  // Simulated async data store
  const users = { 1: "Alice", 2: "Bob", 3: "Charlie" };
  return users[id] ?? null;
}

async function fetchUserName(id) {
  // BUG: missing await — returns Promise instead of name
  const name = getUserById(id);
  return name;
}

module.exports = { fetchUserName, getUserById };
