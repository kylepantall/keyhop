/**
 * Starter sync scripts, embedded so the compiled keyhop.exe ships no loose
 * .ps1/.sh files beside it (antivirus flags those) and setup can still offer them.
 */
import mjs from '../examples/sync.d/50-example.mjs' with { type: 'text' };
import ps1 from '../examples/sync.d/50-example.ps1' with { type: 'text' };
import sh from '../examples/sync.d/50-example.sh' with { type: 'text' };

export const EXAMPLE_SCRIPTS: Record<string, string> = {
  '50-example.mjs': mjs,
  '50-example.ps1': ps1,
  '50-example.sh': sh,
};
