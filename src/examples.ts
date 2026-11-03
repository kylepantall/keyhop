/**
 * Starter sync scripts, embedded so a compiled keyhop.exe (which has no
 * source tree beside it) can still offer them in setup.
 */
import mjs from '../examples/sync.d/50-example.mjs' with { type: 'text' };
import ps1 from '../examples/sync.d/50-example.ps1' with { type: 'text' };
import sh from '../examples/sync.d/50-example.sh' with { type: 'text' };

export const EXAMPLE_SCRIPTS: Record<string, string> = {
  '50-example.mjs': mjs,
  '50-example.ps1': ps1,
  '50-example.sh': sh,
};
