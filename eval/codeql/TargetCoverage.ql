/**
 * Emit every extracted JavaScript/TypeScript function and its source span.
 *
 * @kind table
 * @id provtrail/comparison/target-coverage
 */

import javascript

from Function function
select
  function.getFile().getRelativePath(),
  function.getLocation().getStartLine(),
  function.getLocation().getEndLine()
