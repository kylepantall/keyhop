// Files imported `with { type: 'text' }` (see examples.ts) arrive as strings.
declare module '*.ps1' {
  const text: string;
  export default text;
}
declare module '*.sh' {
  const text: string;
  export default text;
}
declare module '*.mjs' {
  const text: string;
  export default text;
}
