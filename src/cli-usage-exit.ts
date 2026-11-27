/**
 * Commander ends a run it cannot parse with exit 1, which is also the code a
 * scan uses for "critical or high findings". A CI job reading the exit code
 * could not tell a mistyped flag from a finding. This Command subclass keeps
 * Commander's message and help hint and changes only the exit code of a
 * parse error to EXIT_USAGE.
 *
 * Subcommands made with `.command()` are built by `createCommand`, so every
 * subcommand of a program built from this class is one too.
 */
import { Command } from 'commander';
import { EXIT_USAGE } from './check/verdict';

/** The error codes Commander raises when the command line itself is wrong. */
export const USAGE_ERROR_CODES: ReadonlySet<string> = new Set([
  'commander.unknownOption',
  'commander.unknownCommand',
  'commander.missingArgument',
  'commander.optionMissingArgument',
  'commander.missingMandatoryOptionValue',
  'commander.conflictingOption',
  'commander.excessArguments',
  'commander.invalidArgument',
]);

export class UsageExitCommand extends Command {
  createCommand(name?: string): Command {
    return new UsageExitCommand(name);
  }

  error(message: string, errorOptions?: { code?: string; exitCode?: number }): never {
    const code = errorOptions?.code;
    if (code !== undefined && USAGE_ERROR_CODES.has(code)) {
      return super.error(message, { ...errorOptions, exitCode: EXIT_USAGE });
    }
    return super.error(message, errorOptions);
  }
}
