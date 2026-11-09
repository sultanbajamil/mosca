#!/usr/bin/env node
/**
 * MOSCA — executable entry point.
 */

import { main } from '../src/cli.js';

main()
  .then((code) => {
    if (typeof code === 'number' && code !== 0) process.exitCode = code;
  })
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  });
