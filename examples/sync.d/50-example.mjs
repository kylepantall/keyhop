// keyhop sync script (runs with keyhop's Bun).
//
// Print secrets on stdout as one JSON object of strings (or NAME=value lines).
// Steps run in number order — built-in 00-<tool> steps, then 10-…, 20-… — and
// a later step overrides a name set earlier. stderr is shown only if the
// script fails. Exit non-zero to stop the sync; the vault is then left as it was.

const secrets = {};

// A token from an HTTP endpoint you control:
// const res = await fetch('https://vault.internal/token', { headers: { authorization: `Bearer ${process.env.VAULT_TOKEN}` } });
// secrets.INTERNAL_API_TOKEN = (await res.json()).token;

console.log(JSON.stringify(secrets));
