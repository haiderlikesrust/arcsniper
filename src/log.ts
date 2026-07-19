import pino from 'pino'

/**
 * Structured logger. Launch day is a one-shot event with real money on the
 * line, so every state transition and RPC decision gets a timestamped record -
 * if something goes wrong there is no reproducing it later.
 */
export const log = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  base: undefined,
  timestamp: pino.stdTimeFunctions.isoTime,
  // Belt and braces: even if a key or passphrase reaches a log call by mistake,
  // it never lands on disk in the clear.
  redact: {
    paths: [
      'passphrase',
      'privateKey',
      'key',
      '*.passphrase',
      '*.privateKey',
      '*.privateKey',
      'mnemonic',
      '*.mnemonic',
    ],
    censor: '[REDACTED]',
  },
  transport: process.stdout.isTTY
    ? {
        target: 'pino-pretty',
        options: { colorize: true, translateTime: 'HH:MM:ss.l', ignore: 'pid,hostname' },
      }
    : undefined,
})

/** Elapsed-time helper for latency accounting on the critical path. */
export function stopwatch(): () => number {
  const start = process.hrtime.bigint()
  return () => Number(process.hrtime.bigint() - start) / 1e6
}
