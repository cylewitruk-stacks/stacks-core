import {spawn} from 'node:child_process';

const children = [
  spawn('npx', ['tsx', 'watch', 'src/server/index.ts'], {stdio: 'inherit'}),
  spawn('npx', ['vite'], {stdio: 'inherit'}),
];

const stop = (signal) => {
  for (const child of children) child.kill(signal);
};

process.on('SIGINT', () => stop('SIGINT'));
process.on('SIGTERM', () => stop('SIGTERM'));

const statuses = await Promise.all(
  children.map(
    (child) =>
      new Promise((resolve) => child.once('exit', (code) => resolve(code ?? 1))),
  ),
);
process.exit(statuses.find((status) => status !== 0) ?? 0);
